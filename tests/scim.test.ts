import { afterEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { decodeJwt } from "jose";
import { Types } from "mongoose";
import * as GroupItem from "@/app/api/scim/v2/Groups/[id]/route";
import * as Groups from "@/app/api/scim/v2/Groups/route";
import * as Config from "@/app/api/scim/v2/ServiceProviderConfig/route";
import * as UserItem from "@/app/api/scim/v2/Users/[id]/route";
import * as Users from "@/app/api/scim/v2/Users/route";
import { setScimAdminGroups, createScimToken } from "@/lib/scim/tokens";
import { retryLifecycleWebhooks, WebhookDelivery } from "@/lib/webhooks/lifecycle";
import { createSession } from "@/lib/sessions/session-service";
import { createSpace } from "@/lib/spaces/space-service";
import { OAuthClient } from "@/models/OAuthClient";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { Session } from "@/models/Session";
import { SpaceDomain } from "@/models/SpaceDomain";
import { User } from "@/models/User";
import { createTestClient, createTestUser } from "./helpers";

afterEach(() => vi.restoreAllMocks());

const BASE = "http://localhost:3000/api/scim/v2";
type Handler = (req: NextRequest, ctx: { params: Promise<Record<string, string>> }) => Promise<Response>;

async function call(handler: unknown, token: string | null, method: string, path: string, body?: unknown, params: Record<string, string> = {}) {
  const req = new NextRequest(`${BASE}${path}`, { method, headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), "content-type": "application/scim+json" }, body: body === undefined ? undefined : JSON.stringify(body) });
  const res = await (handler as Handler)(req, { params: Promise.resolve(params) });
  return { status: res.status, body: res.status === 204 ? null : ((await res.json()) as Record<string, unknown>) };
}

async function setup() {
  const { user: owner } = await createTestUser({ email: "owner@acme.test" });
  const space = await createSpace({ ownerId: String(owner._id), name: "Acme" });
  await SpaceDomain.create({ organizationId: new Types.ObjectId(space.id), domain: "acme.test", verificationToken: "t", verifiedAt: new Date() });
  const { token } = await createScimToken(String(owner._id), space.id, "Entra provisioning");
  return { owner, space, token };
}

describe("SCIM 2.0 provisioning", () => {
  it("authenticates with the space's token and describes itself", async () => {
    const { token } = await setup();
    expect((await call(Users.GET, null, "GET", "/Users")).status).toBe(401);
    expect((await call(Users.GET, "scim_wrong", "GET", "/Users")).status).toBe(401);
    const config = await call(Config.GET, token, "GET", "/ServiceProviderConfig");
    expect(config.body).toMatchObject({ patch: { supported: true }, filter: { supported: true } });
  });

  it("creates, finds, reconciles, deactivates, reactivates and deletes users, telling apps", async () => {
    const { space, token } = await setup();
    // An app that wants lifecycle events.
    const { client } = await createTestClient();
    await OAuthClient.updateOne({ clientId: client.clientId }, { $set: { lifecycleWebhookUri: "https://app.example.com/lifecycle" } });
    const posted: string[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (_url, init) => {
      posted.push(String((init as RequestInit).body));
      return new Response(null, { status: 200 });
    });

    const created = await call(Users.POST, token, "POST", "/Users", { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: "Ada@acme.test", externalId: "entra-1", name: { givenName: "Ada", familyName: "Lovelace" }, active: true });
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({ userName: "ada@acme.test", externalId: "entra-1", active: true, name: { givenName: "Ada" } });
    const id = created.body!.id as string;
    expect((await User.findById(id).lean())?.emailVerified).toBe(true);
    const events = posted.map((b) => Object.keys(decodeJwt(b).events as object)[0]);
    expect(events).toEqual(expect.arrayContaining(["https://noirly.dev/events/user-created", "https://noirly.dev/events/membership-changed"]));

    // Other domains are not the space's to provision; the same directory id twice is a conflict.
    expect((await call(Users.POST, token, "POST", "/Users", { userName: "x@gmail.com" })).body).toMatchObject({ status: "400", scimType: "invalidValue" });
    expect((await call(Users.POST, token, "POST", "/Users", { userName: "other@acme.test", externalId: "entra-1" })).status).toBe(409);

    // An existing account at the domain is adopted, not duplicated.
    const { user: bob } = await createTestUser({ email: "bob@acme.test" });
    const adopted = await call(Users.POST, token, "POST", "/Users", { userName: "bob@acme.test", externalId: "entra-2" });
    expect(adopted).toMatchObject({ status: 201, body: { id: String(bob._id) } });

    const found = await call(Users.GET, token, "GET", `/Users?filter=${encodeURIComponent('userName eq "ada@acme.test"')}`);
    expect(found.body).toMatchObject({ totalResults: 1, Resources: [{ id }] });
    expect((await call(Users.GET, token, "GET", `/Users?filter=${encodeURIComponent('externalId eq "entra-2"')}`)).body).toMatchObject({ totalResults: 1 });

    // Entra deactivates: account locked, sessions gone, apps told.
    await createSession({ userId: id, methods: ["sso"] });
    posted.length = 0;
    const off = await call(UserItem.PATCH, token, "PATCH", `/Users/${id}`, { schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{ op: "Replace", path: "active", value: "False" }] }, { id });
    expect(off.body).toMatchObject({ active: false });
    const locked = (await User.findById(id).lean())!;
    expect(locked).toMatchObject({ lockKind: "deprovisioned" });
    expect(await Session.countDocuments({ userId: locked._id, revokedAt: null })).toBe(0);
    expect(await OrganizationMembership.exists({ organizationId: new Types.ObjectId(space.id), userId: locked._id })).toBeNull();
    expect(posted.map((b) => Object.keys(decodeJwt(b).events as object)[0])).toContain("https://noirly.dev/events/user-deactivated");

    // Okta reactivates: unlocked, membership back with its directory id.
    const on = await call(UserItem.PATCH, token, "PATCH", `/Users/${id}`, { Operations: [{ op: "replace", value: { active: true } }] }, { id });
    expect(on.body).toMatchObject({ active: true, externalId: "entra-1" });
    expect((await User.findById(id).lean())?.lockedAt).toBeNull();

    // DELETE: gone from the space; the owned account stays locked.
    expect((await call(UserItem.DELETE, token, "DELETE", `/Users/${id}`, undefined, { id })).status).toBe(204);
    expect((await call(UserItem.GET, token, "GET", `/Users/${id}`, undefined, { id })).status).toBe(404);
    expect((await User.findById(id).lean())?.lockKind).toBe("deprovisioned");
  });

  it("syncs groups to teams, and admin groups to roles", async () => {
    const { owner, space, token } = await setup();
    const a = (await call(Users.POST, token, "POST", "/Users", { userName: "a@acme.test", externalId: "e-a" })).body!.id as string;
    const b = (await call(Users.POST, token, "POST", "/Users", { userName: "b@acme.test", externalId: "e-b" })).body!.id as string;
    await setScimAdminGroups(String(owner._id), space.id, ["Platform Admins"]);

    const group = await call(Groups.POST, token, "POST", "/Groups", { displayName: "Platform Admins", externalId: "g1", members: [{ value: a }, { value: String(new Types.ObjectId()) }] });
    expect(group.status).toBe(201);
    const gid = group.body!.id as string;
    expect((group.body!.members as unknown[]).length).toBe(1);
    const role = async (id: string) => (await OrganizationMembership.findOne({ organizationId: new Types.ObjectId(space.id), userId: new Types.ObjectId(id) }).lean())?.role;
    expect(await role(a)).toBe("admin");
    expect(await role(b)).toBe("member");

    // Entra: add b, remove a by filter path.
    await call(GroupItem.PATCH, token, "PATCH", `/Groups/${gid}`, { Operations: [{ op: "Add", path: "members", value: [{ value: b }] }] }, { id: gid });
    await call(GroupItem.PATCH, token, "PATCH", `/Groups/${gid}`, { Operations: [{ op: "Remove", path: `members[value eq "${a}"]` }] }, { id: gid });
    expect(await role(a)).toBe("member");
    expect(await role(b)).toBe("admin");
    expect((await call(Groups.GET, token, "GET", `/Groups?filter=${encodeURIComponent('displayName eq "Platform Admins"')}&excludedAttributes=members`)).body).toMatchObject({ totalResults: 1, Resources: [{ id: gid }] });

    // The owner is never demoted by groups.
    expect(await role(String(owner._id))).toBe("owner");
    expect((await call(GroupItem.DELETE, token, "DELETE", `/Groups/${gid}`, undefined, { id: gid })).status).toBe(204);
    expect(await role(b)).toBe("member");
  });

  it("retries lifecycle webhooks that fail", async () => {
    const { token } = await setup();
    const { client } = await createTestClient();
    await OAuthClient.updateOne({ clientId: client.clientId }, { $set: { lifecycleWebhookUri: "https://app.example.com/lifecycle", lifecycleEvents: ["user.created"] } });
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("down", { status: 503 }));
    await call(Users.POST, token, "POST", "/Users", { userName: "c@acme.test" });
    // Only the event it asked for.
    expect(await WebhookDelivery.countDocuments({})).toBe(1);
    const pending = (await WebhookDelivery.findOne({}).lean())!;
    expect(pending).toMatchObject({ event: "user.created", attempts: 1, lastError: "HTTP 503" });
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }));
    expect(await retryLifecycleWebhooks(new Date(Date.now() + 3600_000))).toBe(0);
    const delivered = (await WebhookDelivery.findOne({}).lean())!;
    expect(delivered.deliveredAt).not.toBeNull();
    // The same txn on the retry, so apps can drop repeats.
    const bodies = fetchMock.mock.calls.map(([, init]) => decodeJwt(String((init as RequestInit).body)).txn);
    expect(new Set(bodies).size).toBe(1);
  });
});
