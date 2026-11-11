import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { decodeJwt } from "jose";
import { afterEach, describe, expect, it } from "vitest";
import { sessionSid } from "@/lib/oidc/sid";
import { createSession, revokeAllUserSessions, validateSession } from "@/lib/sessions/session-service";
import { issueAccessToken, issueRefreshToken, resolveAccessToken, revokeRefreshFamily, rotateRefreshToken } from "@/lib/tokens/token-service";
import { IdentityEvent } from "@/models/IdentityEvent";
import { OAuthClient } from "@/models/OAuthClient";
import { RefreshToken } from "@/models/RefreshToken";
import { Session } from "@/models/Session";
import { createTestClient, createTestUser } from "./helpers";

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

/** An app's back-channel logout endpoint, recording logout tokens. */
async function backchannel() {
  const tokens: string[] = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      tokens.push(new URLSearchParams(body).get("logout_token") ?? "");
      res.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  servers.push(server);
  return { tokens, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/logout` };
}

async function setup() {
  const { user } = await createTestUser();
  const id = String(user._id);
  const { client } = await createTestClient();
  const { token: sessionToken, session } = await createSession({ userId: id });
  const access = await issueAccessToken({ clientId: client.clientId, userId: id, sessionId: session._id, scope: "openid offline_access" });
  const refresh = await issueRefreshToken({ clientId: client.clientId, userId: id, sessionId: session._id, scope: "openid offline_access" });
  return { id, client, session, sessionToken, access, refresh };
}

describe("refresh tokens tied to their session", () => {
  it("are revoked with the session, however it ends", async () => {
    const { id, client, access, refresh } = await setup();
    expect(await revokeAllUserSessions(id)).toBe(1);
    expect(await RefreshToken.countDocuments({ familyId: refresh.familyId, revokedAt: null })).toBe(0);
    expect(await resolveAccessToken(access.token)).toBeNull();
    // Presenting it now is a revoked token presented again.
    expect((await rotateRefreshToken(refresh.token, client.clientId)).error).toBe("reuse_detected");
  });

  it("can't mint anything once the session has expired", async () => {
    const { client, session, refresh } = await setup();
    await Session.updateOne({ _id: session._id }, { $set: { expiresAt: new Date(Date.now() - 1000) } });

    expect(await rotateRefreshToken(refresh.token, client.clientId)).toEqual({ error: "invalid_grant" });
    // Nothing new was minted, and the family is over.
    expect(await RefreshToken.countDocuments({ familyId: refresh.familyId })).toBe(1);
    expect(await RefreshToken.countDocuments({ familyId: refresh.familyId, revokedAt: null })).toBe(0);
  });
});

describe("refresh token reuse", () => {
  it("revokes the whole family everywhere: refresh tokens, the app's access tokens, and its session", async () => {
    const app = await backchannel();
    const { id, client, session, sessionToken, access, refresh } = await setup();
    await OAuthClient.updateOne({ clientId: client.clientId }, { $set: { backchannelLogoutUri: app.url } });
    const other = await createTestClient();
    const otherAccess = await issueAccessToken({ clientId: other.client.clientId, userId: id, sessionId: session._id, scope: "openid" });

    const rotated = await rotateRefreshToken(refresh.token, client.clientId);
    expect(rotated.error).toBeNull();
    const laterAccess = await issueAccessToken({ clientId: client.clientId, userId: id, sessionId: session._id, scope: "openid" });

    // The old token again: someone else has it.
    expect((await rotateRefreshToken(refresh.token, client.clientId)).error).toBe("reuse_detected");
    expect(await RefreshToken.countDocuments({ familyId: refresh.familyId, revokedAt: null })).toBe(0);
    expect(await resolveAccessToken(access.token)).toBeNull();
    expect(await resolveAccessToken(laterAccess.token)).toBeNull();

    // The app is told to end its session; Identity and other apps carry on.
    expect(app.tokens).toHaveLength(1);
    expect(decodeJwt(app.tokens[0]!)).toMatchObject({ aud: client.clientId, sid: sessionSid(session._id) });
    expect(await resolveAccessToken(otherAccess.token)).not.toBeNull();
    expect(await validateSession(sessionToken)).not.toBeNull();

    const event = await IdentityEvent.findOne({ action: "oauth.refresh_reuse_detected" }).lean();
    expect(event?.data).toMatchObject({ familyId: refresh.familyId, familyRevoked: true, accessTokensRevoked: 2 });

    // The newest token in the family is dead too.
    expect((await rotateRefreshToken(rotated.refreshToken!, client.clientId)).error).toBe("reuse_detected");
  });
});

describe("revoking a refresh token", () => {
  it("takes its family and access tokens, but only for the app it was issued to", async () => {
    const { client, access, refresh } = await setup();
    const rotated = await rotateRefreshToken(refresh.token, client.clientId);

    expect(await revokeRefreshFamily(rotated.refreshToken!, "someone-else")).toBe(false);
    expect(await resolveAccessToken(access.token)).not.toBeNull();

    expect(await revokeRefreshFamily(rotated.refreshToken!, client.clientId)).toBe(true);
    expect(await RefreshToken.countDocuments({ familyId: refresh.familyId, revokedAt: null })).toBe(0);
    expect(await resolveAccessToken(access.token)).toBeNull();
  });
});
