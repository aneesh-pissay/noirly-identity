import { describe, expect, it } from "vitest";
import { Types } from "mongoose";
import { parseIdpMetadata, saveProvider, spUrls } from "@/lib/federation/providers";
import { completeFederatedSignIn, finishSaml, parkSamlResponse, readSsoState, serviceProviderMetadata, startSso } from "@/lib/federation/sso";
import { createSpace } from "@/lib/spaces/space-service";
import { IdentityProvider, type IdentityProviderDocument } from "@/models/IdentityProvider";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { SpaceDomain } from "@/models/SpaceDomain";
import { SpaceTeam } from "@/models/SpaceTeam";
import { User } from "@/models/User";
import { IDP_CERT, requestIdOf, samlResponse } from "./support/saml-idp";
import { createTestUser } from "./helpers";

const IDP = "https://idp.acme.test/saml";

async function setup(opts: { jit?: boolean } = {}) {
  const { user: owner } = await createTestUser({ email: "owner@acme.test" });
  const space = await createSpace({ ownerId: String(owner._id), name: "Acme" });
  await SpaceDomain.create({ organizationId: new Types.ObjectId(space.id), domain: "acme.test", verificationToken: "t", verifiedAt: new Date() });
  const team = await SpaceTeam.create({ organizationId: new Types.ObjectId(space.id), name: "Finance" });
  const view = await saveProvider(String(owner._id), space.id, {
    name: "Acme Entra",
    protocol: "saml",
    preset: "entra",
    domains: ["acme.test"],
    jit: opts.jit ?? true,
    saml: { idpEntityId: IDP, ssoUrl: "https://idp.acme.test/sso", certificates: [IDP_CERT] },
    mapping: { roles: [{ group: "admins", role: "admin" }], teams: [{ group: "finance", teamId: String(team._id) }] },
  });
  const idp = (await IdentityProvider.findById(view.id).lean<IdentityProviderDocument>())!;
  return { owner, space, team, idp };
}

const ENTRA = {
  email: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
  given: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
  groups: "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
};

async function signIn(idp: IdentityProviderDocument, nameId: string, attributes: Record<string, string | string[]>, tamper?: (xml: string) => string) {
  const { url, cookie } = await startSso(idp, "/account");
  const state = readSsoState(cookie)!;
  const urls = spUrls(String(idp._id));
  const response = samlResponse({ idpEntityId: IDP, acsUrl: urls.acsUrl, audience: urls.spEntityId, inResponseTo: requestIdOf(url), nameId, attributes, tamper });
  return { state, response, run: async () => finishSaml(state, String(idp._id), await parkSamlResponse(response, state.nonce)) };
}

describe("SAML single sign-on", () => {
  it("creates the account just in time, joins the space and maps groups to role and team", async () => {
    const { idp, space, team } = await setup();
    const { run, state, response } = await signIn(idp, "entra-oid-1", { [ENTRA.email]: "Ada@Acme.test", [ENTRA.given]: "Ada", [ENTRA.groups]: ["admins", "finance"] });
    const { claims } = await run();
    expect(claims).toMatchObject({ subject: "entra-oid-1", email: "ada@acme.test", firstName: "Ada", groups: ["admins", "finance"] });
    const result = await completeFederatedSignIn(idp, claims, {});
    expect(result.created).toBe(true);
    const user = (await User.findOne({ email: "ada@acme.test" }).lean())!;
    expect(user.emailVerified).toBe(true);
    expect((await OrganizationMembership.findOne({ organizationId: new Types.ObjectId(space.id), userId: user._id }).lean())?.role).toBe("admin");
    expect((await SpaceTeam.findById(team._id).lean())?.memberIds.map(String)).toEqual([String(user._id)]);

    // The same response can't be used twice.
    await expect(finishSaml(state, String(idp._id), await parkSamlResponse(response, state.nonce))).rejects.toMatchObject({ code: "sso_invalid" });

    // Groups change at the IdP: role and team follow on the next sign-in.
    const again = await signIn(idp, "entra-oid-1", { [ENTRA.email]: "ada@acme.test", [ENTRA.groups]: [] });
    await completeFederatedSignIn(idp, (await again.run()).claims, {});
    expect((await OrganizationMembership.findOne({ organizationId: new Types.ObjectId(space.id), userId: user._id }).lean())?.role).toBe("member");
    expect((await SpaceTeam.findById(team._id).lean())?.memberIds).toEqual([]);
  });

  it("rejects tampered, foreign-domain and cross-browser answers", async () => {
    const { idp } = await setup();
    const tampered = await signIn(idp, "x", { [ENTRA.email]: "eve@acme.test" }, (xml) => xml.replace("eve@acme.test", "owner@acme.test"));
    await expect(tampered.run()).rejects.toMatchObject({ code: "sso_invalid" });

    const foreign = await signIn(idp, "y", { [ENTRA.email]: "eve@other.test" });
    await expect(completeFederatedSignIn(idp, (await foreign.run()).claims, {})).rejects.toMatchObject({ code: "sso_domain_mismatch" });

    const other = await signIn(idp, "z", { [ENTRA.email]: "zed@acme.test" });
    const parked = await parkSamlResponse(other.response, other.state.nonce);
    await expect(finishSaml({ ...other.state, nonce: "a-different-browser" }, String(idp._id), parked)).rejects.toMatchObject({ code: "sso_state" });
  });

  it("links an existing account at the domain, and without JIT refuses unknown people", async () => {
    const { idp, owner } = await setup({ jit: false });
    const linked = await signIn(idp, "owner-oid", { [ENTRA.email]: "owner@acme.test" });
    const result = await completeFederatedSignIn(idp, (await linked.run()).claims, {});
    expect(result.user.id).toBe(String(owner._id));
    const stranger = await signIn(idp, "new-oid", { [ENTRA.email]: "new@acme.test" });
    await expect(completeFederatedSignIn(idp, (await stranger.run()).claims, {})).rejects.toMatchObject({ code: "sso_no_account" });
  });

  it("allows several providers per space, one per domain, verified domains only", async () => {
    const { idp, owner, space } = await setup();
    const saml = { idpEntityId: "https://idp.labs.test/saml", ssoUrl: "https://idp.labs.test/sso", certificates: [IDP_CERT] };
    await expect(saveProvider(String(owner._id), space.id, { name: "Labs", protocol: "saml", domains: ["labs.test"], saml })).rejects.toMatchObject({ code: "domain_unverified" });
    await SpaceDomain.create({ organizationId: new Types.ObjectId(space.id), domain: "labs.test", verificationToken: "t2", verifiedAt: new Date() });
    await expect(saveProvider(String(owner._id), space.id, { name: "Dup", protocol: "saml", domains: ["acme.test"], saml })).rejects.toMatchObject({ code: "domain_taken" });
    const labs = await saveProvider(String(owner._id), space.id, { name: "Labs", protocol: "saml", domains: ["labs.test"], saml });
    const { findProvider } = await import("@/lib/federation/sso");
    expect(String((await findProvider({ email: "a@acme.test" }))?._id)).toBe(String(idp._id));
    expect(String((await findProvider({ email: "b@labs.test" }))?._id)).toBe(labs.id);
    const { user: member } = await createTestUser({ email: "member@acme.test" });
    await OrganizationMembership.create({ organizationId: new Types.ObjectId(space.id), userId: member._id, role: "member" });
    await expect(saveProvider(String(member._id), space.id, { name: "Mine", protocol: "saml", domains: ["labs.test"], saml })).rejects.toMatchObject({ status: 403 });
  });

  it("exchanges metadata both ways", async () => {
    const { idp } = await setup();
    const sp = serviceProviderMetadata(idp);
    expect(sp).toContain(spUrls(String(idp._id)).acsUrl);
    expect(sp).toContain(`entityID="${spUrls(String(idp._id)).spEntityId}"`);
    const body = IDP_CERT.replace(/-----[A-Z ]+-----|\s/g, "");
    const parsed = parseIdpMetadata(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="${IDP}"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${body}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.acme.test/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`);
    expect(parsed).toEqual({ idpEntityId: IDP, ssoUrl: "https://idp.acme.test/sso", certificates: [body] });
  });
});
