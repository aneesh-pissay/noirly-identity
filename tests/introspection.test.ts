import { describe, expect, it } from "vitest";
import { NextRequest } from "next/server";
import { POST as introspect } from "@/app/api/oauth/introspect/route";
import { buildDiscoveryDocument } from "@/lib/oidc/discovery";
import { sessionSid } from "@/lib/oidc/sid";
import { createSession, revokeSession } from "@/lib/sessions/session-service";
import { issueAccessToken, issueRefreshToken, rotateRefreshToken } from "@/lib/tokens/token-service";
import { AccessToken } from "@/models/AccessToken";
import { Session } from "@/models/Session";
import { User } from "@/models/User";
import { createTestClient, createTestUser } from "./helpers";

function ask(body: Record<string, string>, authorization?: string) {
  return introspect(new NextRequest("http://localhost:3000/api/oauth/introspect", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", ...(authorization ? { authorization } : {}) },
    body: new URLSearchParams(body).toString(),
  }));
}
const basic = (id: string, secret: string) => `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`;

async function setup() {
  const { user } = await createTestUser();
  const id = String(user._id);
  const app = await createTestClient();
  const api = await createTestClient();
  const { session } = await createSession({ userId: id, methods: ["password"] });
  const access = await issueAccessToken({ clientId: app.client.clientId, userId: id, sessionId: session._id, scope: "openid profile" });
  const refresh = await issueRefreshToken({ clientId: app.client.clientId, userId: id, sessionId: session._id, scope: "openid offline_access" });
  return { id, app, api, session, access, refresh, apiAuth: basic(api.client.clientId, api.clientSecret) };
}

describe("token introspection (RFC 7662)", () => {
  it("describes a live access token to an API", async () => {
    const { id, app, session, access, apiAuth } = await setup();
    const response = await ask({ token: access.token }, apiAuth);
    expect(response.headers.get("cache-control")).toContain("no-store");
    const body = await response.json();
    expect(body).toMatchObject({ active: true, token_type: "Bearer", scope: "openid profile", client_id: app.client.clientId, sub: id, iss: "http://localhost:3000", sid: sessionSid(session._id) });
    expect(body.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(body.exp - body.iat).toBeLessThanOrEqual(3600);
    expect(typeof body.auth_time).toBe("number");
  });

  it("says only inactive for tokens that are expired, revoked, from an ended or idle session, or a disabled account", async () => {
    const { id, session, access, apiAuth } = await setup();
    const inactive = async () => expect(await (await ask({ token: access.token }, apiAuth)).json()).toEqual({ active: false });

    await AccessToken.updateOne({ tokenHash: { $exists: true } }, { $set: { expiresAt: new Date(Date.now() - 1000) } });
    await inactive();
    await AccessToken.updateOne({}, { $set: { expiresAt: new Date(Date.now() + 3_600_000) } });

    await User.updateOne({ _id: id }, { $set: { status: "disabled" } });
    await inactive();
    await User.updateOne({ _id: id }, { $set: { status: "active" } });

    await Session.updateOne({ _id: session._id }, { $set: { idleTimeoutSeconds: 900, lastActivityAt: new Date(Date.now() - 1_000_000) } });
    await inactive();
    await Session.updateOne({ _id: session._id }, { $set: { idleTimeoutSeconds: null } });
    expect((await (await ask({ token: access.token }, apiAuth)).json()).active).toBe(true);

    await revokeSession(session._id);
    await inactive();
    expect(await (await ask({ token: "made-up" }, apiAuth)).json()).toEqual({ active: false });
  });

  it("shows a refresh token only to the app it was issued to, and never a rotated-away one", async () => {
    const { app, refresh, apiAuth } = await setup();
    const own = basic(app.client.clientId, app.clientSecret);
    expect(await (await ask({ token: refresh.token, token_type_hint: "refresh_token" }, apiAuth)).json()).toEqual({ active: false });
    expect(await (await ask({ token: refresh.token, token_type_hint: "refresh_token" }, own)).json()).toMatchObject({ active: true, token_type: "refresh_token", scope: "openid offline_access" });

    const rotated = await rotateRefreshToken(refresh.token, app.client.clientId);
    expect(await (await ask({ token: refresh.token }, own)).json()).toEqual({ active: false });
    // A wrong hint doesn't matter.
    expect((await (await ask({ token: rotated.refreshToken!, token_type_hint: "access_token" }, own)).json()).active).toBe(true);
  });

  it("needs a confidential app that proves who it is", async () => {
    const { access, api } = await setup();
    expect((await ask({ token: access.token })).status).toBe(401);
    expect((await ask({ token: access.token }, basic(api.client.clientId, "wrong"))).status).toBe(401);
    // Form credentials work too.
    expect((await (await ask({ token: access.token, client_id: api.client.clientId, client_secret: api.clientSecret })).json()).active).toBe(true);
    const mobile = await createTestClient({ clientType: "public" });
    expect((await ask({ token: access.token, client_id: mobile.client.clientId })).status).toBe(401);
    expect((await ask({}, basic(api.client.clientId, api.clientSecret))).status).toBe(400);
    expect(buildDiscoveryDocument()).toMatchObject({ introspection_endpoint: "http://localhost:3000/api/oauth/introspect" });
  });
});
