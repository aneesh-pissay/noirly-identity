import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { decodeJwt } from "jose";
import { GET as authorize } from "@/app/api/oauth/authorize/route";
import { POST as checkRoute } from "@/app/api/authz/check/route";
import { GET as permissionsRoute } from "@/app/api/authz/permissions/route";
import { assignRole, saveRole, setMemberAttributes } from "@/lib/authz/admin";
import { explain } from "@/lib/authz/engine";
import { getEnv } from "@/lib/config/env";
import { exchangeAuthorizationCode } from "@/lib/oauth/token";
import { buildUserInfo } from "@/lib/oidc/userinfo";
import { generateSecureToken } from "@/lib/security/crypto";
import { createSession } from "@/lib/sessions/session-service";
import { createSpace } from "@/lib/spaces/space-service";
import { issueAccessToken } from "@/lib/tokens/token-service";
import { Organization } from "@/models/Organization";
import { createTestClient, createTestUser, pkceChallenge } from "./helpers";

const jar = vi.hoisted(() => new Map<string, string>());
vi.mock("next/headers", () => ({ cookies: async () => ({ get: (key: string) => (jar.has(key) ? { value: jar.get(key) } : undefined) }) }));
beforeEach(() => jar.clear());

async function setup(methods: Array<"password" | "passkey"> = ["password"], place: string | null = null) {
  const { user: owner } = await createTestUser({ email: "owner@example.com" });
  const { user: alice } = await createTestUser({ email: "alice@example.com" });
  const ownerId = String(owner._id);
  const aliceId = String(alice._id);
  const space = await createSpace({ ownerId, name: "Books", members: [{ userId: aliceId, role: "member" }] });
  const role = await saveRole(ownerId, space.id, { name: "Accountant", permissions: ["invoice:read", "invoice:approve"] });
  const { client, clientSecret } = await createTestClient({ allowedScopes: ["openid", "offline_access", "permissions"] });
  const { token, session } = await createSession({ userId: aliceId, methods, place });
  jar.set(getEnv().SESSION_COOKIE_NAME, token);
  return { ownerId, aliceId, space, role, client, clientSecret, session };
}

async function tokensFor(client: { clientId: string; redirectUris: string[] }, clientSecret: string, organization: string, scope = "openid permissions") {
  const verifier = generateSecureToken(32);
  const url = new URL("http://localhost:3000/api/oauth/authorize");
  for (const [k, v] of Object.entries({ client_id: client.clientId, redirect_uri: client.redirectUris[0]!, response_type: "code", scope, state: "st", code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", organization })) url.searchParams.set(k, v);
  const code = new URL((await authorize(new NextRequest(url))).headers.get("location")!).searchParams.get("code")!;
  return exchangeAuthorizationCode({ code, redirectUri: client.redirectUris[0]!, codeVerifier: verifier, clientId: client.clientId, clientSecret, authorizationHeader: null });
}

const check = (token: string, permission: string, resource?: string) =>
  checkRoute(new NextRequest("http://localhost:3000/api/authz/check", { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify({ permission, resource }) }));

describe("permissions delivered to apps", () => {
  it("as a permissions claim on tokens scoped to an organization", async () => {
    const { ownerId, aliceId, space, role, client, clientSecret } = await setup();
    await assignRole(ownerId, space.id, { roleId: role.id, subjectType: "user", subjectId: aliceId });
    const tokens = await tokensFor(client, clientSecret, space.id);
    expect(decodeJwt(tokens.id_token).permissions).toEqual(["invoice:approve", "invoice:read"]);
    expect((await buildUserInfo(tokens.access_token)).permissions).toEqual(["invoice:approve", "invoice:read"]);
  });

  it("through the permissions API, live and denied by default", async () => {
    const { ownerId, aliceId, space, role, client, clientSecret } = await setup();
    const tokens = await tokensFor(client, clientSecret, space.id);
    expect(await (await check(tokens.access_token, "invoice:read")).json()).toEqual({ allowed: false });
    const assignment = await assignRole(ownerId, space.id, { roleId: role.id, subjectType: "user", subjectId: aliceId, resource: "ledger/*" });
    expect(await (await check(tokens.access_token, "invoice:read", "ledger/1")).json()).toEqual({ allowed: true });
    expect(await (await check(tokens.access_token, "invoice:read", "payroll/1")).json()).toEqual({ allowed: false });
    expect(await (await permissionsRoute(new NextRequest("http://localhost:3000/api/authz/permissions", { headers: { authorization: `Bearer ${tokens.access_token}` } }))).json()).toEqual({ org_id: space.id, permissions: ["invoice:approve@ledger/*", "invoice:read@ledger/*"] });
    void assignment;

    // Bad tokens, unscoped tokens and bad permissions are refused.
    expect((await check("nonsense", "invoice:read")).status).toBe(401);
    const { session } = await createSession({ userId: aliceId });
    const unscoped = await issueAccessToken({ clientId: client.clientId, userId: aliceId, sessionId: session._id, scope: "openid" });
    expect((await check(unscoped.token, "invoice:read")).status).toBe(400);
    expect((await check(tokens.access_token, "Invoice Read")).status).toBe(400);
  });
});

describe("conditional rules", () => {
  it("hold an assignment to a department and a trusted device", async () => {
    const { ownerId, aliceId, space, role } = await setup();
    await assignRole(ownerId, space.id, { roleId: role.id, subjectType: "user", subjectId: aliceId, conditions: [{ attribute: "department", op: "eq", value: "finance" }, { attribute: "device", op: "eq", value: "trusted" }] });
    const subject = { type: "user" as const, id: aliceId };
    expect((await explain(space.id, subject, "invoice:read", null, { deviceTrusted: true })).notApplied[0]?.reason).toBe("department is not set, needs eq finance");
    await setMemberAttributes(ownerId, space.id, aliceId, { department: "Finance" });
    expect(await explain(space.id, subject, "invoice:read", null, { deviceTrusted: false })).toMatchObject({ allowed: false });
    expect(await explain(space.id, subject, "invoice:read", null, { deviceTrusted: true })).toMatchObject({ allowed: true });
  });

  it("hold one to working hours and days, in the organization's time zone", async () => {
    const { ownerId, aliceId, space, role } = await setup();
    await Organization.updateOne({ _id: space.id }, { $set: { timeZone: "Asia/Kolkata" } });
    await assignRole(ownerId, space.id, { roleId: role.id, subjectType: "user", subjectId: aliceId, conditions: [{ attribute: "time", op: "between", value: "09:00-18:00" }, { attribute: "weekday", op: "in", value: "mon,tue,wed,thu,fri" }] });
    const subject = { type: "user" as const, id: aliceId };
    // Tuesday 10:00 in Kolkata is 04:30 UTC.
    expect((await explain(space.id, subject, "invoice:read", null, { now: new Date("2026-11-10T04:30:00Z") })).allowed).toBe(true);
    // Tuesday 20:00 in Kolkata.
    expect((await explain(space.id, subject, "invoice:read", null, { now: new Date("2026-11-10T14:30:00Z") })).notApplied[0]?.reason).toBe("outside 09:00-18:00");
    // Saturday 10:00 in Kolkata.
    expect((await explain(space.id, subject, "invoice:read", null, { now: new Date("2026-11-14T04:30:00Z") })).allowed).toBe(false);
  });

  it("see the sign-in behind the token: passkey and country", async () => {
    const { ownerId, aliceId, space, role, client, clientSecret } = await setup(["passkey"], "Mumbai, IN");
    await assignRole(ownerId, space.id, { roleId: role.id, subjectType: "user", subjectId: aliceId, conditions: [{ attribute: "device", op: "eq", value: "trusted" }, { attribute: "country", op: "in", value: "IN,GB" }] });
    const tokens = await tokensFor(client, clientSecret, space.id);
    expect(await (await check(tokens.access_token, "invoice:approve")).json()).toEqual({ allowed: true });
    await expect(assignRole(ownerId, space.id, { roleId: role.id, subjectType: "user", subjectId: aliceId, conditions: [{ attribute: "time", op: "eq", value: "9" }] })).rejects.toMatchObject({ code: "invalid_condition" });
  });
});
