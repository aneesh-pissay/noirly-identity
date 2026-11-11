import { afterEach, describe, expect, it, vi } from "vitest";
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { Types } from "mongoose";
import { discoverSignIn } from "@/lib/auth/discovery";
import { resetEmailProvider, setEmailProvider, type EmailMessage } from "@/lib/email/email-service";
import { checkFederationCertificates } from "@/lib/federation/certificates";
import { setSsoEnforcement } from "@/lib/federation/enforcement";
import { saveProvider } from "@/lib/federation/providers";
import { completeFederatedSignIn, finishOidc, readSsoState, resetJwksCache, startSso } from "@/lib/federation/sso";
import { listEvents } from "@/lib/audit/event-log";
import { createSession } from "@/lib/sessions/session-service";
import { createSpace } from "@/lib/spaces/space-service";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { IdentityProvider, type IdentityProviderDocument } from "@/models/IdentityProvider";
import { Mfa } from "@/models/SecurityCredential";
import { Session } from "@/models/Session";
import { SpaceDomain } from "@/models/SpaceDomain";
import { IDP_CERT, NEXT_IDP_CERT } from "./support/saml-idp";
import { createTestUser } from "./helpers";

const ISSUER = "https://acme.okta.com";
let key: { privateKey: CryptoKey; jwk: Record<string, unknown> };
let sent: EmailMessage[] = [];

afterEach(() => {
  vi.restoreAllMocks();
  resetJwksCache();
  resetEmailProvider();
});

async function fakeOkta(idToken: () => Promise<string>, metadata?: string) {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  key = { privateKey, jwk: { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256", use: "sig" } };
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const url = String(input);
    if (url === `${ISSUER}/.well-known/openid-configuration`) return Response.json({ issuer: ISSUER, authorization_endpoint: `${ISSUER}/oauth2/v1/authorize`, token_endpoint: `${ISSUER}/oauth2/v1/token`, jwks_uri: `${ISSUER}/oauth2/v1/keys` });
    if (url === `${ISSUER}/oauth2/v1/token`) return Response.json({ id_token: await idToken(), access_token: "x", token_type: "Bearer" });
    if (url === `${ISSUER}/oauth2/v1/keys`) return Response.json({ keys: [key.jwk] });
    if (metadata && url === "https://idp.acme.test/metadata") return new Response(metadata);
    return new Response("not found", { status: 404 });
  });
}

async function setup() {
  sent = [];
  setEmailProvider({ send: async (m) => { sent.push(m); } });
  const { user: owner } = await createTestUser({ email: "owner@acme.test" });
  const space = await createSpace({ ownerId: String(owner._id), name: "Acme" });
  await SpaceDomain.create({ organizationId: new Types.ObjectId(space.id), domain: "acme.test", verificationToken: "t", verifiedAt: new Date() });
  return { owner, space };
}

describe("OIDC single sign-on (Okta preset)", () => {
  it("discovers the provider, verifies the ID token and signs in", async () => {
    let nonce = "";
    await fakeOkta(() => new SignJWT({ nonce, email: "grace@acme.test", email_verified: true, given_name: "Grace", family_name: "Hopper", groups: ["eng"] }).setProtectedHeader({ alg: "RS256", kid: "k1" }).setIssuer(ISSUER).setAudience("okta-client").setSubject("00u1").setIssuedAt().setExpirationTime("5m").sign(key.privateKey));
    const { owner, space } = await setup();
    const view = await saveProvider(String(owner._id), space.id, { name: "Okta", protocol: "oidc", preset: "okta", domains: ["acme.test"], oidc: { oktaDomain: "acme.okta.com", clientId: "okta-client", clientSecret: "s3cret" } });
    expect(view.oidc).toMatchObject({ issuer: ISSUER, hasSecret: true, scopes: ["openid", "email", "profile", "groups"] });
    const idp = (await IdentityProvider.findById(view.id).lean<IdentityProviderDocument>())!;

    const { url, cookie } = await startSso(idp, "/account", "grace@acme.test");
    expect(new URL(url).searchParams.get("code_challenge_method")).toBe("S256");
    const state = readSsoState(cookie)!;
    nonce = state.nonce;
    const { claims } = await finishOidc(state, { code: "abc", state: state.nonce, error: null });
    expect(claims).toMatchObject({ subject: "00u1", email: "grace@acme.test", firstName: "Grace", lastName: "Hopper", groups: ["eng"] });
    const result = await completeFederatedSignIn(idp, claims, {});
    expect(result.created).toBe(true);
    const tokenCall = vi.mocked(fetch).mock.calls.find(([u]) => String(u).endsWith("/token"))!;
    expect(String((tokenCall[1] as RequestInit).body)).toContain("client_secret=s3cret");

    // A wrong nonce (a token minted for another sign-in) is refused.
    nonce = "something-else";
    await expect(finishOidc(state, { code: "abc", state: state.nonce, error: null })).rejects.toMatchObject({ code: "sso_invalid" });
    await expect(finishOidc(state, { code: "abc", state: "forged", error: null })).rejects.toMatchObject({ code: "sso_state" });
  });

  it("enforces SSO for the domain, with audited break-glass access", async () => {
    await fakeOkta(async () => "unused");
    const { owner, space } = await setup();
    const { user: member } = await createTestUser({ email: "dev@acme.test" });
    await OrganizationMembership.create({ organizationId: new Types.ObjectId(space.id), userId: member._id, role: "member" });
    await createSession({ userId: String(member._id), methods: ["password"] });
    await expect(setSsoEnforcement(String(owner._id), space.id, { enforced: true })).rejects.toMatchObject({ code: "no_provider" });
    await saveProvider(String(owner._id), space.id, { name: "Okta", protocol: "oidc", preset: "okta", domains: ["acme.test"], oidc: { oktaDomain: "acme.okta.com", clientId: "c" } });

    // Break-glass accounts need a second step.
    await expect(setSsoEnforcement(String(owner._id), space.id, { breakGlassEmails: ["owner@acme.test"] })).rejects.toMatchObject({ code: "second_step_required" });
    await Mfa.create({ userId: owner._id, enabled: true, secret: "sealed" });
    await setSsoEnforcement(String(owner._id), space.id, { enforced: true, breakGlassEmails: ["owner@acme.test"] });

    // Members' non-SSO sessions end; new ones are refused; SSO ones are fine.
    expect(await Session.countDocuments({ userId: member._id, revokedAt: null })).toBe(0);
    await expect(createSession({ userId: String(member._id), methods: ["password"] })).rejects.toMatchObject({ code: "sso_required" });
    await expect(createSession({ userId: String(member._id), methods: ["sso"] })).resolves.toBeTruthy();

    // Break-glass: only with a second step, recorded and emailed to owners.
    await expect(createSession({ userId: String(owner._id), methods: ["password"] })).rejects.toMatchObject({ code: "sso_required" });
    await createSession({ userId: String(owner._id), methods: ["password", "totp"] });
    expect((await listEvents({ action: "sso.break_glass_used" })).events).toHaveLength(1);
    expect(sent.filter((m) => m.subject.startsWith("Break-glass"))).toHaveLength(1);

    // Email-first sign-in sends the domain to its IdP and offers nothing else.
    expect(await discoverSignIn("dev@acme.test")).toMatchObject({ password: false, emailLink: false, sso: { name: "Okta", required: true, startUrl: "/api/sso/start?email=dev%40acme.test" } });
    expect((await discoverSignIn("someone@elsewhere.test")).sso).toBeUndefined();
  });
});

describe("federation certificates", () => {
  it("warns owners once before expiry, and picks up rotations from metadata", async () => {
    const body = (pem: string) => pem.replace(/-----[A-Z ]+-----|\s/g, "");
    const metadata = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.acme.test/saml"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${body(NEXT_IDP_CERT)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.acme.test/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`;
    await fakeOkta(async () => "unused", metadata);
    const { owner, space } = await setup();
    const view = await saveProvider(String(owner._id), space.id, { name: "Acme SAML", protocol: "saml", domains: ["acme.test"], saml: { idpEntityId: "https://idp.acme.test/saml", ssoUrl: "https://idp.acme.test/sso", certificates: [IDP_CERT] } });
    await IdentityProvider.updateOne({ _id: view.id }, { $set: { "saml.certificates.0.notAfter": new Date(Date.now() + 10 * 86_400_000) } });

    expect(await checkFederationCertificates()).toMatchObject({ expiring: 1, rotated: 0 });
    expect(sent.filter((m) => m.subject.includes("expires soon")).map((m) => m.to)).toEqual(["owner@acme.test"]);
    expect(await checkFederationCertificates()).toMatchObject({ expiring: 0 });

    // The IdP publishes its next certificate: picked up, and the warning stops mattering.
    await IdentityProvider.updateOne({ _id: view.id }, { $set: { "saml.metadataUrl": "https://idp.acme.test/metadata" } });
    expect(await checkFederationCertificates()).toMatchObject({ rotated: 1, expiring: 0 });
    expect((await IdentityProvider.findById(view.id).lean())?.saml?.certificates).toHaveLength(2);

    // Past expiry, the old one is dropped (a valid one remains).
    await IdentityProvider.updateOne({ _id: view.id }, { $set: { "saml.certificates.0.notAfter": new Date(Date.now() - 1000) } });
    expect(await checkFederationCertificates()).toMatchObject({ removed: 1 });
  });
});
