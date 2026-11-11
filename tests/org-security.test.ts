import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { GET as authorize } from "@/app/api/oauth/authorize/route";
import { getEnv } from "@/lib/config/env";
import { generateSecureToken } from "@/lib/security/crypto";
import { accountSessionPolicy, sessionPolicyFor, setSessionPolicy } from "@/lib/sessions/lifetime";
import { createSession, validateSession } from "@/lib/sessions/session-service";
import { getOrgSecurity, setOrgSecurity, signInMeetsOrgMethods } from "@/lib/spaces/org-security";
import { createSpace, setAdminAreas } from "@/lib/spaces/space-service";
import { Session } from "@/models/Session";
import { createTestClient, createTestUser, pkceChallenge } from "./helpers";

const jar = vi.hoisted(() => new Map<string, string>());
vi.mock("next/headers", () => ({ cookies: async () => ({ get: (key: string) => (jar.has(key) ? { value: jar.get(key) } : undefined) }) }));
beforeEach(() => jar.clear());

const HOUR = 3600;
const DAY = 86_400;

async function setup() {
  const { user: owner } = await createTestUser({ email: "owner@example.com" });
  const { user: alice } = await createTestUser({ email: "alice@example.com" });
  const { user: admin } = await createTestUser({ email: "admin@example.com" });
  const space = await createSpace({ ownerId: String(owner._id), name: "Bank", members: [{ userId: String(alice._id), role: "member" }, { userId: String(admin._id), role: "admin" }] });
  return { ownerId: String(owner._id), aliceId: String(alice._id), adminId: String(admin._id), space };
}

async function openApp(userId: string, methods: Array<"password" | "google" | "passkey">, organization: string, extra: Record<string, string> = {}) {
  const { client } = await createTestClient();
  const { token } = await createSession({ userId, methods });
  jar.clear();
  jar.set(getEnv().SESSION_COOKIE_NAME, token);
  const url = new URL("http://localhost:3000/api/oauth/authorize");
  for (const [k, v] of Object.entries({ client_id: client.clientId, redirect_uri: client.redirectUris[0]!, response_type: "code", scope: "openid", state: "st", code_challenge: pkceChallenge(generateSecureToken(32)), code_challenge_method: "S256", organization, ...extra })) url.searchParams.set(k, v);
  return new URL((await authorize(new NextRequest(url))).headers.get("location")!);
}

describe("organization security policies", () => {
  it("require one of the allowed ways of signing in to open apps in the organization", async () => {
    const { ownerId, aliceId, space } = await setup();
    expect(await signInMeetsOrgMethods(space.id, ["password"])).toEqual({ ok: true, allowed: [] });
    await setOrgSecurity(ownerId, space.id, { allowedMethods: ["passkey", "google"] });

    const withPassword = await openApp(aliceId, ["password"], space.id);
    expect(withPassword.pathname).toBe("/login");
    expect(withPassword.searchParams.get("reauth")).toBe("1");
    expect((await openApp(aliceId, ["password"], space.id, { prompt: "none" })).searchParams.get("error")).toBe("login_required");
    expect((await openApp(aliceId, ["google"], space.id)).searchParams.get("code")).toBeTruthy();
    // Outside the organization, the person's own sign-in is theirs to choose.
    const { client } = await createTestClient();
    const { token } = await createSession({ userId: aliceId, methods: ["password"] });
    jar.set(getEnv().SESSION_COOKIE_NAME, token);
    const url = new URL("http://localhost:3000/api/oauth/authorize");
    for (const [k, v] of Object.entries({ client_id: client.clientId, redirect_uri: client.redirectUris[0]!, response_type: "code", scope: "openid", state: "st", code_challenge: pkceChallenge(generateSecureToken(32)), code_challenge_method: "S256" })) url.searchParams.set(k, v);
    expect(new URL((await authorize(new NextRequest(url))).headers.get("location")!).searchParams.get("code")).toBeTruthy();
  });

  it("limit members' sessions to the strictest of theirs and every organization's, live sessions included", async () => {
    const { ownerId, aliceId, space } = await setup();
    const old = await createSession({ userId: aliceId });
    await Session.updateOne({ _id: old.session._id }, { $set: { createdAt: new Date(Date.now() - 2 * DAY * 1000) } });
    const recent = await createSession({ userId: aliceId });

    await setOrgSecurity(ownerId, space.id, { sessionPolicy: { idleSeconds: null, absoluteSeconds: DAY } });
    expect(await sessionPolicyFor(aliceId)).toEqual({ idleSeconds: null, absoluteSeconds: DAY });
    expect(await validateSession(old.token)).toBeNull();
    expect(await validateSession(recent.token)).not.toBeNull();

    // Her own stricter choice wins where it's stricter; the organization's where it is.
    const session = await createSession({ userId: aliceId });
    await setSessionPolicy(aliceId, { idleSeconds: HOUR, absoluteSeconds: 7 * DAY }, String(session.session._id));
    expect(await accountSessionPolicy(aliceId)).toEqual({ idleSeconds: HOUR, absoluteSeconds: 7 * DAY });
    expect(await sessionPolicyFor(aliceId)).toEqual({ idleSeconds: HOUR, absoluteSeconds: DAY });
    // New sessions follow the effective policy.
    const fresh = await createSession({ userId: aliceId });
    expect(fresh.session.expiresAt.getTime() - Date.now()).toBeLessThanOrEqual(DAY * 1000);
    expect(fresh.session.idleTimeoutSeconds).toBe(HOUR);
  });

  it("are set by admins with the settings area, and seen by members", async () => {
    const { ownerId, adminId, aliceId, space } = await setup();
    await setOrgSecurity(adminId, space.id, { allowedMethods: ["passkey"] });
    await setAdminAreas(ownerId, space.id, adminId, ["members"]);
    await expect(setOrgSecurity(adminId, space.id, { allowedMethods: [] })).rejects.toMatchObject({ status: 403 });
    await expect(setOrgSecurity(aliceId, space.id, { allowedMethods: [] })).rejects.toMatchObject({ status: 403 });
    await expect(setOrgSecurity(ownerId, space.id, { allowedMethods: ["totp"] })).rejects.toMatchObject({ status: 400 });
    await expect(setOrgSecurity(ownerId, space.id, { sessionPolicy: { idleSeconds: 60, absoluteSeconds: null } })).rejects.toMatchObject({ status: 400 });
    expect(await getOrgSecurity(aliceId, space.id)).toMatchObject({ allowedMethods: ["passkey"], requireMfa: false });
  });
});
