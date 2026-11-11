import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { GET as authorize } from "@/app/api/oauth/authorize/route";
import { POST as sessionCheck } from "@/app/api/oidc/session/route";
import { getEnv } from "@/lib/config/env";
import { buildDiscoveryDocument } from "@/lib/oidc/discovery";
import { sessionSid } from "@/lib/oidc/sid";
import { generateSecureToken } from "@/lib/security/crypto";
import { setSessionPolicy } from "@/lib/sessions/lifetime";
import { createSession, revokeSession } from "@/lib/sessions/session-service";
import { issueAccessToken } from "@/lib/tokens/token-service";
import { OAuthClient } from "@/models/OAuthClient";
import { Session } from "@/models/Session";
import { User } from "@/models/User";
import { createTestClient, createTestUser, pkceChallenge } from "./helpers";

const jar = vi.hoisted(() => new Map<string, string>());
vi.mock("next/headers", () => ({ cookies: async () => ({ get: (key: string) => (jar.has(key) ? { value: jar.get(key) } : undefined) }) }));
beforeEach(() => jar.clear());

function authorizeUrl(clientId: string, redirectUri: string, extra: Record<string, string> = {}) {
  const url = new URL("http://localhost:3000/api/oauth/authorize");
  const verifier = generateSecureToken(32);
  for (const [k, v] of Object.entries({ client_id: clientId, redirect_uri: redirectUri, response_type: "code", scope: "openid profile", state: "st", code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", prompt: "none", ...extra })) url.searchParams.set(k, v);
  return url;
}

const where = (response: Response) => new URL(response.headers.get("location")!);

async function signedIn() {
  const { user } = await createTestUser();
  const { token, session } = await createSession({ userId: user._id, methods: ["password"] });
  jar.set(getEnv().SESSION_COOKIE_NAME, token);
  return { user, id: String(user._id), session };
}

describe("silent single sign-on (prompt=none)", () => {
  it("hands back a code with no page when already signed in, and login_required when not", async () => {
    const { client } = await createTestClient();
    const anonymous = where(await authorize(new NextRequest(authorizeUrl(client.clientId, client.redirectUris[0]!))));
    expect(anonymous.searchParams.get("error")).toBe("login_required");
    expect(anonymous.searchParams.get("state")).toBe("st");

    await signedIn();
    const silent = where(await authorize(new NextRequest(authorizeUrl(client.clientId, client.redirectUris[0]!))));
    expect(silent.origin + silent.pathname).toBe(client.redirectUris[0]);
    expect(silent.searchParams.get("code")).toBeTruthy();
  });

  it("skips consent it can't show only when the app already has every scope it asks for", async () => {
    const { client } = await createTestClient({ requireConsent: true });
    const { id, session } = await signedIn();
    const url = () => authorizeUrl(client.clientId, client.redirectUris[0]!);

    expect(where(await authorize(new NextRequest(url()))).searchParams.get("error")).toBe("consent_required");

    // Agreed to before (a token was issued with these scopes).
    await issueAccessToken({ clientId: client.clientId, userId: id, sessionId: session._id, scope: "openid profile" });
    expect(where(await authorize(new NextRequest(url()))).searchParams.get("code")).toBeTruthy();

    // Asking for more than was agreed still needs the page.
    const more = where(await authorize(new NextRequest(authorizeUrl(client.clientId, client.redirectUris[0]!, { scope: "openid profile email" }))));
    expect(more.searchParams.get("error")).toBe("consent_required");
    // And an interactive request still shows consent as before.
    const interactive = where(await authorize(new NextRequest(authorizeUrl(client.clientId, client.redirectUris[0]!, { prompt: "consent" }))));
    expect(interactive.pathname).toBe("/consent");
  });

  it("answers interaction_required, not a page, when the address isn't confirmed yet", async () => {
    const { client } = await createTestClient();
    const { id } = await signedIn();
    await User.updateOne({ _id: id }, { $set: { emailVerified: false } });
    const response = where(await authorize(new NextRequest(authorizeUrl(client.clientId, client.redirectUris[0]!))));
    expect(response.searchParams.get("error")).toBe("interaction_required");
  });
});

function check(body: Record<string, string>, authorization?: string) {
  return sessionCheck(new NextRequest("http://localhost:3000/api/oidc/session", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", ...(authorization ? { authorization } : {}) },
    body: new URLSearchParams(body).toString(),
  }));
}

describe("session check", () => {
  it("answers for an access token's session, and never counts as activity", async () => {
    const { client } = await createTestClient();
    const { id, session } = await signedIn();
    const access = await issueAccessToken({ clientId: client.clientId, userId: id, sessionId: session._id, scope: "openid" });
    const before = (await Session.findById(session._id).lean())!.lastActivityAt;
    await Session.updateOne({ _id: session._id }, { $set: { lastActivityAt: new Date(Date.now() - 60 * 60_000) } });

    const live = await (await check({}, `Bearer ${access.token}`)).json();
    expect(live).toMatchObject({ active: true, sid: sessionSid(session._id) });
    expect(live.expires_at).toBe(Math.floor(session.expiresAt.getTime() / 1000));
    expect(typeof live.auth_time).toBe("number");
    expect((await Session.findById(session._id).lean())!.lastActivityAt.getTime()).toBeLessThan(before.getTime());

    await revokeSession(session._id);
    expect(await (await check({}, `Bearer ${access.token}`)).json()).toEqual({ active: false });
    expect(await (await check({}, "Bearer nonsense")).json()).toEqual({ active: false });
  });

  it("answers a confidential app by sid, only for sessions that signed in to it, and counts idle limits", async () => {
    const { client, clientSecret } = await createTestClient();
    const other = await createTestClient();
    const { id, session } = await signedIn();
    await issueAccessToken({ clientId: client.clientId, userId: id, sessionId: session._id, scope: "openid" });
    const sid = sessionSid(session._id);
    const basic = `Basic ${Buffer.from(`${client.clientId}:${clientSecret}`).toString("base64")}`;

    expect(await (await check({ sid }, basic)).json()).toMatchObject({ active: true, sid });
    // Another app can't learn about a session that never reached it.
    expect(await (await check({ sid, client_id: other.client.clientId, client_secret: other.clientSecret })).json()).toEqual({ active: false });
    // A wrong secret is refused outright.
    expect((await check({ sid, client_id: client.clientId, client_secret: "wrong" })).status).toBe(401);

    // With an idle limit, the answer says when it'll lapse, and a lapsed one is inactive.
    await setSessionPolicy(id, { idleSeconds: 15 * 60, absoluteSeconds: null }, "000000000000000000000000");
    const idle = await (await check({ sid }, basic)).json();
    expect(idle.active).toBe(true);
    expect(idle.expires_at).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + 15 * 60);
    await Session.updateOne({ _id: session._id }, { $set: { lastActivityAt: new Date(Date.now() - 16 * 60_000) } });
    expect(await (await check({ sid }, basic)).json()).toEqual({ active: false });
  });

  it("makes public apps use their access token, and is in discovery", async () => {
    const { client } = await createTestClient({ clientType: "public" });
    await OAuthClient.updateOne({ _id: client._id }, { $set: { status: "active" } });
    expect((await check({ sid: "x", client_id: client.clientId })).status).toBe(401);
    expect(buildDiscoveryDocument()).toMatchObject({ noirly_session_check_endpoint: "http://localhost:3000/api/oidc/session", backchannel_logout_supported: true });
  });
});
