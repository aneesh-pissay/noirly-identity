import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { decodeJwt, importSPKI, jwtVerify } from "jose";
import { afterEach, describe, expect, it } from "vitest";
import { BACKCHANNEL_LOGOUT_EVENT, frontchannelLogoutUrls, retryPendingLogoutNotices } from "@/lib/oidc/backchannel-logout";
import { createIdToken } from "@/lib/oidc/id-token";
import { sessionSid } from "@/lib/oidc/sid";
import { logoutUri } from "@/lib/oauth/client-admin";
import { signOutOfApp, signOutSessions } from "@/lib/sessions/devices";
import { createSession, revokeAllUserSessions, revokeSessionByToken } from "@/lib/sessions/session-service";
import { issueAccessToken } from "@/lib/tokens/token-service";
import { LogoutNotice } from "@/models/LogoutNotice";
import { OAuthClient } from "@/models/OAuthClient";
import { User } from "@/models/User";
import { createTestClient, createTestUser } from "./helpers";

/** A local app back-channel endpoint that records logout tokens (or fails while `status` says so). */
async function startApp() {
  const app = { tokens: [] as string[], status: 200, url: "", server: null as Server | null };
  app.server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      app.tokens.push(new URLSearchParams(body).get("logout_token") ?? "");
      res.statusCode = app.status;
      res.end();
    });
  });
  await new Promise<void>((resolve) => app.server!.listen(0, "127.0.0.1", resolve));
  app.url = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}/backchannel-logout`;
  servers.push(app.server);
  return app;
}

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

async function appClient(uris: { backchannel?: string; frontchannel?: string }) {
  const { client } = await createTestClient();
  await OAuthClient.updateOne({ _id: client._id }, { $set: { backchannelLogoutUri: uris.backchannel ?? null, frontchannelLogoutUri: uris.frontchannel ?? null } });
  return client.clientId;
}

/** A session signed in to these apps. */
async function sessionWith(userId: string, clientIds: string[]) {
  const created = await createSession({ userId });
  for (const clientId of clientIds) await issueAccessToken({ clientId, userId, sessionId: created.session._id, scope: "openid" });
  return created;
}

describe("coordinated logout", () => {
  it("POSTs a signed logout token to each app the session reached, naming the sid its ID token had", async () => {
    const app = await startApp();
    const { user } = await createTestUser();
    const id = String(user._id);
    const withBackchannel = await appClient({ backchannel: app.url });
    const without = await appClient({});
    const notReached = await appClient({ backchannel: app.url });
    void notReached;
    const { token, session } = await sessionWith(id, [withBackchannel, without]);

    const ended = await revokeSessionByToken(token);
    expect(ended.backchannelFailed).toEqual([]);
    expect(app.tokens).toHaveLength(1);
    const key = await importSPKI(process.env.JWT_PUBLIC_KEY!.replace(/\\n/g, "\n"), "RS256");
    const { payload, protectedHeader } = await jwtVerify(app.tokens[0]!, key, { issuer: "http://localhost:3000", audience: withBackchannel });
    expect(protectedHeader.typ).toBe("logout+jwt");
    expect(payload).toMatchObject({ sub: id, sid: sessionSid(session._id), events: { [BACKCHANNEL_LOGOUT_EVENT]: {} } });
    expect(payload.nonce).toBeUndefined();
    expect(payload.jti).toBeTruthy();

    const userDoc = await User.findById(id);
    const idToken = decodeJwt(await createIdToken({ user: userDoc!, clientId: withBackchannel, scope: "openid", authTime: new Date(), sessionId: session._id }));
    expect(idToken.sid).toBe(payload.sid);
    // Derived, not the database id.
    expect(idToken.sid).not.toBe(String(session._id));
  });

  it("tells apps about every session a sign-out-everywhere ends, and devices signed out from the account page", async () => {
    const app = await startApp();
    const { user } = await createTestUser();
    const id = String(user._id);
    const clientId = await appClient({ backchannel: app.url });
    const here = await sessionWith(id, [clientId]);
    const phone = await sessionWith(id, [clientId]);
    const laptop = await sessionWith(id, [clientId]);

    await signOutSessions(id, [String(phone.session._id)], String(here.session._id));
    expect(app.tokens.map((t) => decodeJwt(t).sid)).toEqual([sessionSid(phone.session._id)]);

    // A password change: everywhere but here.
    expect(await revokeAllUserSessions(id, here.session._id)).toBe(1);
    expect(app.tokens.map((t) => decodeJwt(t).sid)).toEqual([sessionSid(phone.session._id), sessionSid(laptop.session._id)]);
  });

  it("signs one app out without a sid when it's every device, and only that app", async () => {
    const app = await startApp();
    const other = await startApp();
    const { user } = await createTestUser();
    const id = String(user._id);
    const crm = await appClient({ backchannel: app.url });
    const docs = await appClient({ backchannel: other.url });
    const here = await sessionWith(id, [crm, docs]);
    await sessionWith(id, [crm]);

    await signOutOfApp(id, crm, String(here.session._id));
    expect(decodeJwt(app.tokens[0]!).sid).toBe(sessionSid(here.session._id));

    await signOutOfApp(id, crm, null);
    const everywhere = decodeJwt(app.tokens[1]!);
    expect(everywhere.sub).toBe(id);
    expect(everywhere.sid).toBeUndefined();
    expect(app.tokens).toHaveLength(2);
    expect(other.tokens).toHaveLength(0);
  });

  it("keeps failed deliveries for retry, and falls back to front-channel for them", async () => {
    const app = await startApp();
    const ok = await startApp();
    app.status = 503;
    const { user } = await createTestUser();
    const id = String(user._id);
    const failing = await appClient({ backchannel: app.url, frontchannel: "https://crm.example.com/logout?from=identity" });
    const working = await appClient({ backchannel: ok.url, frontchannel: "https://docs.example.com/logout" });
    const frontOnly = await appClient({ frontchannel: "https://flow.example.com/logout" });
    const { token, session } = await sessionWith(id, [failing, working, frontOnly]);

    const ended = await revokeSessionByToken(token);
    expect(ended.backchannelFailed).toEqual([failing]);
    expect(await LogoutNotice.countDocuments({ clientId: failing })).toBe(1);

    const urls = (await frontchannelLogoutUrls(ended.session!, ended.backchannelFailed)).map((u) => new URL(u));
    expect(urls.map((u) => u.host).sort()).toEqual(["crm.example.com", "flow.example.com"]);
    const crm = urls.find((u) => u.host === "crm.example.com")!;
    expect(crm.searchParams.get("from")).toBe("identity");
    expect(crm.searchParams.get("iss")).toBe("http://localhost:3000");
    expect(crm.searchParams.get("sid")).toBe(sessionSid(session._id));

    // Still down: kept. Back up: delivered, gone.
    expect(await retryPendingLogoutNotices()).toBe(1);
    app.status = 200;
    expect(await retryPendingLogoutNotices()).toBe(0);
    expect(await LogoutNotice.countDocuments()).toBe(0);
    expect(decodeJwt(app.tokens.at(-1)!).sid).toBe(sessionSid(session._id));
  });

  it("only takes logout URIs that are https, or http on localhost in development", () => {
    expect(logoutUri("https://crm.example.com/api/logout", "Back-channel logout URI")).toBe("https://crm.example.com/api/logout");
    expect(logoutUri("http://localhost:3001/logout", "Back-channel logout URI")).toBe("http://localhost:3001/logout");
    expect(logoutUri("", "Back-channel logout URI")).toBeNull();
    expect(() => logoutUri("http://crm.example.com/logout", "Back-channel logout URI")).toThrow(/https/);
    expect(() => logoutUri("https://crm.example.com/logout#x", "Back-channel logout URI")).toThrow(/fragment/);
    expect(() => logoutUri("/logout", "Back-channel logout URI")).toThrow(/absolute/);
  });
});
