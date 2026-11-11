import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { GET as listClients, POST as registerClient } from "@/app/api/admin/clients/route";
import { PATCH as patchClient, DELETE as deleteClient } from "@/app/api/admin/clients/[clientId]/route";
import { POST as addEnvironment } from "@/app/api/admin/clients/[clientId]/environments/route";
import { getEnv } from "@/lib/config/env";
import { addAppEnvironment, registerAppClient } from "@/lib/oauth/client-admin";
import { setAppOwners } from "@/lib/oauth/app-owners";
import { createSession } from "@/lib/sessions/session-service";
import { OAuthClient } from "@/models/OAuthClient";
import { User } from "@/models/User";
import { createTestUser } from "./helpers";

const jar = vi.hoisted(() => new Map<string, string>());
vi.mock("next/headers", () => ({ cookies: async () => ({ get: (key: string) => (jar.has(key) ? { value: jar.get(key) } : undefined) }) }));
beforeEach(() => jar.clear());

async function signIn(email: string, admin = false) {
  const { user } = await createTestUser({ email });
  if (admin) await User.updateOne({ _id: user._id }, { $set: { roles: ["user", "admin"] } });
  const { token } = await createSession({ userId: user._id });
  return { user, token };
}
function as(token: string) {
  jar.clear();
  jar.set(getEnv().SESSION_COOKIE_NAME, token);
  jar.set(getEnv().CSRF_COOKIE_NAME, "csrf");
}
const json = (method: string, url: string, body?: unknown) =>
  new NextRequest(url, { method, headers: { "content-type": "application/json", "x-csrf-token": "csrf", origin: "http://localhost:3000" }, ...(body ? { body: JSON.stringify(body) } : {}) });
const params = (clientId: string) => ({ params: Promise.resolve({ clientId }) });

async function setup() {
  const admin = await signIn("admin@example.com", true);
  const owner = await signIn("owner@example.com");
  const stranger = await signIn("stranger@example.com");
  await registerAppClient({ clientId: "noirly-crm", name: "Noirly CRM", origins: ["https://crm.noirly.com"], environment: "production" });
  await registerAppClient({ clientId: "noirly-docs", name: "Noirly Docs", origins: ["https://docs.noirly.com"], environment: "production" });
  await setAppOwners("noirly-crm", ["owner@example.com"]);
  return { admin, owner, stranger };
}

describe("app owners", () => {
  it("are set by email on every environment of an app, and only for verified accounts", async () => {
    await setup();
    await addAppEnvironment("noirly-crm", { environment: "staging", origins: ["https://staging.crm.noirly.com"] });
    const staging = await OAuthClient.findOne({ clientId: "noirly-crm-staging" }).lean();
    expect(staging?.ownerIds?.map(String)).toHaveLength(1);
    await expect(setAppOwners("noirly-crm", ["nobody@example.com"])).rejects.toMatchObject({ code: "unknown_owner" });
    await setAppOwners("noirly-crm", []);
    expect((await OAuthClient.find({ appKey: "noirly-crm" }).lean()).every((c) => (c.ownerIds ?? []).length === 0)).toBe(true);
  });

  it("see and manage only their own app, and can't register or delete apps", async () => {
    const { owner } = await setup();
    as(owner.token);
    const listed = await (await listClients()).json();
    expect(listed.clients.map((c: { clientId: string }) => c.clientId)).toEqual(["noirly-crm"]);
    expect(listed.owners).toEqual({ [String(owner.user._id)]: "owner@example.com" });

    // Their app's settings, environments and secret.
    const patched = await patchClient(json("PATCH", "http://localhost:3000/api/admin/clients/noirly-crm", { redirectUris: ["https://crm.noirly.com/cb"], replaceUris: true }), params("noirly-crm"));
    expect(patched.status).toBe(200);
    expect((await patchClient(json("PATCH", "http://localhost:3000/api/admin/clients/noirly-crm", { rotateSecret: true }), params("noirly-crm"))).status).toBe(200);
    expect((await addEnvironment(json("POST", "http://localhost:3000/api/admin/clients/noirly-crm/environments", { environment: "development", origins: ["http://localhost:3001"] }), params("noirly-crm"))).status).toBe(201);
    // Co-owners too.
    await signIn("colleague@example.com");
    expect((await patchClient(json("PATCH", "http://localhost:3000/api/admin/clients/noirly-crm", { owners: ["owner@example.com", "colleague@example.com"] }), params("noirly-crm"))).status).toBe(200);

    // Someone else's app looks missing; registering and deleting are for admins.
    expect((await patchClient(json("PATCH", "http://localhost:3000/api/admin/clients/noirly-docs", { name: "Mine now" }), params("noirly-docs"))).status).toBe(404);
    expect((await deleteClient(json("DELETE", "http://localhost:3000/api/admin/clients/noirly-crm"), params("noirly-crm"))).status).toBe(403);
    expect((await registerClient(json("POST", "http://localhost:3000/api/admin/clients", { clientId: "sneaky", name: "Sneaky", origins: ["https://sneaky.example.com"] }))).status).toBe(403);
  });

  it("aren't anyone else: a signed-in stranger gets nothing, an admin gets everything", async () => {
    const { stranger, admin } = await setup();
    as(stranger.token);
    expect((await listClients()).status).toBe(403);
    expect((await patchClient(json("PATCH", "http://localhost:3000/api/admin/clients/noirly-crm", { name: "x" }), params("noirly-crm"))).status).toBe(404);
    as(admin.token);
    const all = await (await listClients()).json();
    expect(all.clients.map((c: { clientId: string }) => c.clientId).sort()).toEqual(["noirly-crm", "noirly-docs"]);
    expect((await patchClient(json("PATCH", "http://localhost:3000/api/admin/clients/noirly-docs", { owners: ["stranger@example.com"] }), params("noirly-docs"))).status).toBe(200);
  });
});
