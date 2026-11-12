import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Types } from "mongoose";
import { notifyAccountDeleted, retryPendingDeletionNotices } from "@/lib/account/deletion-webhooks";
import { resetEnvCache } from "@/lib/config/env";
import { deactivateMember, reactivateMember } from "@/lib/directory/lifecycle";
import { resetEmailProvider, setEmailProvider, type EmailMessage } from "@/lib/email/email-service";
import { setSsoEnforcement } from "@/lib/federation/enforcement";
import { saveProvider } from "@/lib/federation/providers";
import { completeFederatedSignIn } from "@/lib/federation/sso";
import { createScimToken, revokeScimToken } from "@/lib/scim/tokens";
import { createScimUser } from "@/lib/scim/users";
import { createSession } from "@/lib/sessions/session-service";
import { createSpace } from "@/lib/spaces/space-service";
import { retryLifecycleWebhooks, WebhookDelivery } from "@/lib/webhooks/lifecycle";
import { IdentityProvider, type IdentityProviderDocument } from "@/models/IdentityProvider";
import { OAuthClient } from "@/models/OAuthClient";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { Mfa } from "@/models/SecurityCredential";
import { Session } from "@/models/Session";
import { SpaceDomain } from "@/models/SpaceDomain";
import { User } from "@/models/User";
import { IDP_CERT } from "./support/saml-idp";
import { createTestClient, createTestUser } from "./helpers";

let sent: EmailMessage[] = [];
beforeEach(() => {
  sent = [];
  setEmailProvider({ send: async (m) => { sent.push(m); } });
});
afterEach(() => {
  resetEmailProvider();
  vi.restoreAllMocks();
  delete process.env.ACCOUNT_DELETION_WEBHOOKS;
  resetEnvCache();
});

const to = (address: string) => sent.filter((m) => m.to === address).map((m) => m.subject);

async function setup() {
  const { user: owner } = await createTestUser({ email: "owner@acme.test" });
  const space = await createSpace({ ownerId: String(owner._id), name: "Acme" });
  const org = new Types.ObjectId(space.id);
  await SpaceDomain.create({ organizationId: org, domain: "acme.test", verificationToken: "t", verifiedAt: new Date() });
  const { user: domainsAdmin } = await createTestUser({ email: "it@acme.test" });
  await OrganizationMembership.create({ organizationId: org, userId: domainsAdmin._id, role: "admin", adminAreas: ["domains"] });
  const { user: member } = await createTestUser({ email: "dev@acme.test" });
  await OrganizationMembership.create({ organizationId: org, userId: member._id, role: "member" });
  return { owner, ownerId: String(owner._id), space, org, member };
}

async function samlProvider(ownerId: string, spaceId: string) {
  const view = await saveProvider(ownerId, spaceId, { name: "Acme Entra", protocol: "saml", domains: ["acme.test"], saml: { idpEntityId: "https://idp.acme.test", ssoUrl: "https://idp.acme.test/sso", certificates: [IDP_CERT] } });
  return (await IdentityProvider.findById(view.id).lean<IdentityProviderDocument>())!;
}

describe("notices to a space's owners", () => {
  it("go to owners and domain admins (not members) when SSO or SCIM tokens change", async () => {
    const { ownerId, space } = await setup();
    await samlProvider(ownerId, space.id);
    expect(to("owner@acme.test")).toEqual(["Single sign-on added in Acme"]);
    expect(to("it@acme.test")).toEqual(["Single sign-on added in Acme"]);
    expect(to("dev@acme.test")).toEqual([]);
    expect(sent[0]!.text).toContain("Acme Entra");

    sent = [];
    const token = await createScimToken(ownerId, space.id, "Entra provisioning");
    await revokeScimToken(ownerId, space.id, token.id);
    expect(to("owner@acme.test")).toEqual(["New provisioning token in Acme", "Provisioning token revoked in Acme"]);
    // The token itself is never in an email.
    expect(sent.some((m) => m.text.includes(token.token))).toBe(false);
  });

  it("explain SSO enforcement, and tell people signed out why (their tokens revoked too)", async () => {
    const { owner, ownerId, space, member } = await setup();
    await samlProvider(ownerId, space.id);
    await Mfa.create({ userId: owner._id, enabled: true, secret: "sealed" });
    await createSession({ userId: String(member._id), methods: ["password"] });
    await createSession({ userId: String(member._id), methods: ["sso"] });
    sent = [];

    await setSsoEnforcement(ownerId, space.id, { enforced: true });
    expect(to("owner@acme.test")).toEqual(["Acme now requires single sign-on"]);
    expect(sent.find((m) => m.to === "owner@acme.test")!.text).toContain("no break-glass accounts");
    expect(to("dev@acme.test")).toEqual(["Sign in through Acme's single sign-on"]);
    // The SSO session stays; the password one ended.
    expect(await Session.countDocuments({ userId: member._id, revokedAt: null })).toBe(1);
  });
});

describe("notices to people an organization manages", () => {
  it("welcome accounts made by SSO or SCIM, and tell adopted accounts who manages them", async () => {
    const { ownerId, space } = await setup();
    const idp = await samlProvider(ownerId, space.id);
    sent = [];
    await completeFederatedSignIn(idp, { subject: "oid-1", email: "new@acme.test", firstName: "New", lastName: "Person", groups: [] }, {});
    expect(to("new@acme.test")).toEqual(["Your Noirly account, through Acme"]);

    await createScimUser(space.id, { userName: "scim@acme.test" });
    expect(to("scim@acme.test")).toEqual(["Acme made you a Noirly account"]);
    await createTestUser({ email: "existing@acme.test" });
    await createScimUser(space.id, { userName: "existing@acme.test" });
    expect(to("existing@acme.test")).toEqual(["You've been added to Acme"]);
    // Provisioned already inactive: nothing about being added.
    await createScimUser(space.id, { userName: "inactive@acme.test", active: false });
    expect(to("inactive@acme.test")).toEqual(["Acme turned off your Noirly account"]);
  });

  it("tell people when they're deactivated and reactivated, in words that fit whose address it is", async () => {
    const { ownerId, space, org, member } = await setup();
    const { user: outsider } = await createTestUser({ email: "contractor@elsewhere.test" });
    await OrganizationMembership.create({ organizationId: org, userId: outsider._id, role: "member" });
    sent = [];

    await deactivateMember(space.id, String(member._id), { actorId: ownerId, via: "admin" });
    await deactivateMember(space.id, String(outsider._id), { actorId: ownerId, via: "admin" });
    expect(to("dev@acme.test")).toEqual(["Acme turned off your Noirly account"]);
    expect(to("contractor@elsewhere.test")).toEqual(["You no longer have access to Acme"]);

    await reactivateMember(space.id, String(member._id), { actorId: ownerId, via: "admin" });
    await reactivateMember(space.id, String(outsider._id), { actorId: ownerId, via: "admin" });
    expect(to("dev@acme.test").at(-1)).toBe("Acme turned your Noirly account back on");
    expect(to("contractor@elsewhere.test").at(-1)).toBe("You're back in Acme");
  });
});

describe("notices to Identity's admins", () => {
  async function admin() {
    const { user } = await createTestUser({ email: "root@noirly.test" });
    await User.updateOne({ _id: user._id }, { $set: { roles: ["user", "admin"] } });
  }

  it("say once per run which apps gave up on deletion notices", async () => {
    await admin();
    process.env.ACCOUNT_DELETION_WEBHOOKS = "noirly-flow=https://flow.example.com/deleted";
    resetEnvCache();
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("down", { status: 503 }));
    await notifyAccountDeleted("sub-a");
    await notifyAccountDeleted("sub-b");
    expect(to("root@noirly.test")).toEqual([]);
    await retryPendingDeletionNotices(2);
    expect(to("root@noirly.test")).toEqual(["Apps never confirmed account deletions"]);
    expect(sent.find((m) => m.to === "root@noirly.test")!.text).toContain("noirly-flow (2 accounts)");
  });

  it("say which apps stopped receiving lifecycle events", async () => {
    await admin();
    const { client } = await createTestClient();
    await OAuthClient.updateOne({ clientId: client.clientId }, { $set: { lifecycleWebhookUri: "https://app.example.com/lifecycle" } });
    await WebhookDelivery.create({ txn: "t1", clientId: client.clientId, event: "user.deactivated", sub: "u1", data: {}, attempts: 9, nextAttemptAt: new Date(Date.now() - 1000), expiresAt: new Date(Date.now() + 86_400_000) });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("down", { status: 500 }));
    await retryLifecycleWebhooks();
    expect(to("root@noirly.test")).toEqual(["Apps stopped receiving lifecycle events"]);
  });
});
