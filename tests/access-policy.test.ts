import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { GET as authorize } from "@/app/api/oauth/authorize/route";
import { getEnv } from "@/lib/config/env";
import { describePolicy, mayUseApp, setAccessPolicy } from "@/lib/oauth/access-policy";
import { exchangeRefreshToken } from "@/lib/oauth/token";
import { generateSecureToken } from "@/lib/security/crypto";
import { createSession } from "@/lib/sessions/session-service";
import { createSpace, removeMember } from "@/lib/spaces/space-service";
import { issueRefreshToken } from "@/lib/tokens/token-service";
import { OAuthClient } from "@/models/OAuthClient";
import { createTestClient, createTestUser, pkceChallenge } from "./helpers";

const jar = vi.hoisted(() => new Map<string, string>());
vi.mock("next/headers", () => ({ cookies: async () => ({ get: (key: string) => (jar.has(key) ? { value: jar.get(key) } : undefined) }) }));
beforeEach(() => jar.clear());

async function person(email: string) {
  const { user } = await createTestUser({ email });
  return { user, id: String(user._id) };
}

async function authorizeAs(userId: string, client: { clientId: string; redirectUris: string[] }, extra: Record<string, string> = {}) {
  const { token } = await createSession({ userId, methods: ["password"] });
  jar.clear();
  jar.set(getEnv().SESSION_COOKIE_NAME, token);
  const url = new URL("http://localhost:3000/api/oauth/authorize");
  for (const [k, v] of Object.entries({ client_id: client.clientId, redirect_uri: client.redirectUris[0]!, response_type: "code", scope: "openid", state: "st", code_challenge: pkceChallenge(generateSecureToken(32)), code_challenge_method: "S256", ...extra })) url.searchParams.set(k, v);
  return new URL((await authorize(new NextRequest(url))).headers.get("location")!);
}

describe("per-app access policies", () => {
  it("let anyone in by default", async () => {
    const { id } = await person("a@example.com");
    const { client } = await createTestClient();
    expect(await mayUseApp(client, id)).toBe(true);
    expect((await authorizeAs(id, client)).searchParams.get("code")).toBeTruthy();
  });

  it("admit only members of the chosen spaces, and cut off someone who leaves at the next refresh", async () => {
    const alice = await person("alice@example.com");
    const bob = await person("bob@example.com");
    const space = await createSpace({ ownerId: alice.id, name: "Finance", members: [{ userId: bob.id, role: "member" }] });
    const outsider = await person("outsider@example.com");
    const { client, clientSecret } = await createTestClient();
    expect((await setAccessPolicy(client.clientId, { mode: "spaces", spaces: [space.slug] })).summary).toBe("Members of Finance");
    const stored = (await OAuthClient.findOne({ clientId: client.clientId }).lean())!;

    expect((await authorizeAs(bob.id, client)).searchParams.get("code")).toBeTruthy();
    const denied = await authorizeAs(outsider.id, client);
    expect(denied.pathname).toBe("/no-access");
    expect(denied.searchParams.get("client_id")).toBe(client.clientId);
    expect((await authorizeAs(outsider.id, client, { prompt: "none" })).searchParams.get("error")).toBe("access_denied");

    // Bob holds a refresh token, then leaves the space.
    const { session } = await createSession({ userId: bob.id });
    const refresh = await issueRefreshToken({ clientId: client.clientId, userId: bob.id, sessionId: session._id, scope: "openid offline_access" });
    await removeMember(bob.id, space.id, bob.id);
    expect(await mayUseApp(stored, bob.id)).toBe(false);
    await expect(exchangeRefreshToken({ refreshToken: refresh.token, clientId: client.clientId, clientSecret, authorizationHeader: null })).rejects.toMatchObject({ error: "invalid_grant" });
  });

  it("admit only the listed people, and refuse unknown spaces or people", async () => {
    const listed = await person("listed@example.com");
    const other = await person("other@example.com");
    const { client } = await createTestClient();
    expect(await setAccessPolicy(client.clientId, { mode: "allowlist", emails: ["Listed@Example.com"] })).toMatchObject({ summary: "1 person", people: ["listed@example.com"] });
    const stored = (await OAuthClient.findOne({ clientId: client.clientId }).lean())!;
    expect(await mayUseApp(stored, listed.id)).toBe(true);
    expect(await mayUseApp(stored, other.id)).toBe(false);

    await expect(setAccessPolicy(client.clientId, { mode: "allowlist", emails: ["nobody@example.com"] })).rejects.toMatchObject({ code: "unknown_user" });
    await expect(setAccessPolicy(client.clientId, { mode: "spaces", spaces: ["no-such-space"] })).rejects.toMatchObject({ code: "unknown_space" });
    await expect(setAccessPolicy(client.clientId, { mode: "spaces", spaces: [] })).rejects.toMatchObject({ status: 400 });
    // Back to anyone.
    await setAccessPolicy(client.clientId, { mode: "anyone" });
    expect(await describePolicy((await OAuthClient.findOne({ clientId: client.clientId }).lean())!)).toMatchObject({ mode: "anyone" });
  });
});
