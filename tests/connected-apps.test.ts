import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { decodeJwt } from "jose";
import { GET as authorize } from "@/app/api/oauth/authorize/route";
import { listAppAccess, noteTokenIssued, removeAppAccess } from "@/lib/account/app-access";
import { getEnv } from "@/lib/config/env";
import { generateSecureToken } from "@/lib/security/crypto";
import { createSession, validateSession } from "@/lib/sessions/session-service";
import { issueAccessToken, issueRefreshToken, resolveAccessToken } from "@/lib/tokens/token-service";
import { AppAccess } from "@/models/AppAccess";
import { IdentityEvent } from "@/models/IdentityEvent";
import { OAuthClient } from "@/models/OAuthClient";
import { RefreshToken } from "@/models/RefreshToken";
import { Session } from "@/models/Session";
import { createTestClient, createTestUser, pkceChallenge } from "./helpers";

const jar = vi.hoisted(() => new Map<string, string>());
vi.mock("next/headers", () => ({ cookies: async () => ({ get: (key: string) => (jar.has(key) ? { value: jar.get(key) } : undefined) }) }));
beforeEach(() => jar.clear());

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

async function backchannel() {
  const tokens: string[] = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => { tokens.push(new URLSearchParams(body).get("logout_token") ?? ""); res.end(); });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  servers.push(server);
  return { tokens, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/logout` };
}

describe("connected apps", () => {
  it("say what each app may see and since when", async () => {
    const { user } = await createTestUser();
    const { client } = await createTestClient();
    const monday = new Date("2026-11-02T09:00:00Z");
    const wednesday = new Date("2026-11-04T09:00:00Z");
    await noteTokenIssued(user._id, client.clientId, "openid email", monday);
    await noteTokenIssued(user._id, client.clientId, "openid email profile", wednesday);
    const [app] = await listAppAccess(String(user._id));
    expect(app?.grants).toEqual([
      { scope: "openid", text: "That it's you, by your Noirly account ID", since: monday.toISOString() },
      { scope: "profile", text: expect.stringContaining("Your name"), since: wednesday.toISOString() },
      { scope: "email", text: "Your primary email address and whether it's confirmed", since: monday.toISOString() },
    ]);
  });

  it("can have their access removed: tokens end, the app is told, devices forget it, other apps carry on", async () => {
    const app = await backchannel();
    const { user } = await createTestUser();
    const id = String(user._id);
    const { client } = await createTestClient();
    const other = await createTestClient();
    await OAuthClient.updateOne({ clientId: client.clientId }, { $set: { backchannelLogoutUri: app.url } });
    const { token: sessionToken, session } = await createSession({ userId: id });
    const access = await issueAccessToken({ clientId: client.clientId, userId: id, sessionId: session._id, scope: "openid email" });
    await issueRefreshToken({ clientId: client.clientId, userId: id, sessionId: session._id, scope: "openid offline_access" });
    const keep = await issueAccessToken({ clientId: other.client.clientId, userId: id, sessionId: session._id, scope: "openid" });

    expect(await removeAppAccess(id, client.clientId, { ipAddress: "203.0.113.9" })).toEqual({ revoked: 2 });
    expect(await resolveAccessToken(access.token)).toBeNull();
    expect(await RefreshToken.countDocuments({ clientId: client.clientId, revokedAt: null })).toBe(0);
    expect(await resolveAccessToken(keep.token)).not.toBeNull();
    expect(await validateSession(sessionToken)).not.toBeNull();

    // Told to end every session of this person there.
    expect(app.tokens).toHaveLength(1);
    expect(decodeJwt(app.tokens[0]!)).toMatchObject({ aud: client.clientId, sub: id });
    expect(decodeJwt(app.tokens[0]!).sid).toBeUndefined();

    // Gone from the list (and the devices list), the rest stay; the account's log says so.
    expect((await listAppAccess(id)).map((a) => a.clientId)).toEqual([other.client.clientId]);
    expect((await Session.findById(session._id).lean())?.appIds).toEqual([other.client.clientId]);
    expect(await IdentityEvent.countDocuments({ action: "oauth.access_removed", clientId: client.clientId })).toBe(1);

    // Removing it twice says so.
    await expect(removeAppAccess(id, client.clientId)).rejects.toMatchObject({ status: 404 });
  });

  it("make the app ask again, even one that normally skips consent, and silently can't get round it", async () => {
    const { user } = await createTestUser();
    const id = String(user._id);
    const { client } = await createTestClient({ requireConsent: false });
    const { token, session } = await createSession({ userId: id, methods: ["password"] });
    jar.set(getEnv().SESSION_COOKIE_NAME, token);
    await issueAccessToken({ clientId: client.clientId, userId: id, sessionId: session._id, scope: "openid" });

    const run = async (extra: Record<string, string> = {}) => {
      const url = new URL("http://localhost:3000/api/oauth/authorize");
      for (const [k, v] of Object.entries({ client_id: client.clientId, redirect_uri: client.redirectUris[0]!, response_type: "code", scope: "openid", state: "st", code_challenge: pkceChallenge(generateSecureToken(32)), code_challenge_method: "S256", ...extra })) url.searchParams.set(k, v);
      return new URL((await authorize(new NextRequest(url))).headers.get("location")!);
    };
    expect((await run()).searchParams.get("code")).toBeTruthy();

    await removeAppAccess(id, client.clientId);
    expect((await run()).pathname).toBe("/consent");
    expect((await run({ prompt: "none" })).searchParams.get("error")).toBe("consent_required");

    // Agreeing again (the consent route) puts it back to normal.
    await AppAccess.updateOne({ userId: user._id, clientId: client.clientId }, { $set: { consentRequired: false } });
    expect((await run()).searchParams.get("code")).toBeTruthy();
  });

  it("come back into the list once the app is used again", async () => {
    const { user } = await createTestUser();
    const { client } = await createTestClient();
    await noteTokenIssued(user._id, client.clientId, "openid email");
    await removeAppAccess(String(user._id), client.clientId);
    expect(await listAppAccess(String(user._id))).toEqual([]);
    await noteTokenIssued(user._id, client.clientId, "openid");
    const [app] = await listAppAccess(String(user._id));
    // A fresh start: only what was granted since.
    expect(app?.scopes).toEqual(["openid"]);
  });
});
