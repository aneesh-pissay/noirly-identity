import { describe, expect, it } from "vitest";
import { placeFromRequest } from "@/lib/api/request";
import { listDeviceSessions, signOutOfApp, signOutOtherSessions, signOutSessions } from "@/lib/sessions/devices";
import { IdentityEvent } from "@/models/IdentityEvent";
import { OAuthClient } from "@/models/OAuthClient";
import { createSession, validateSession } from "@/lib/sessions/session-service";
import { issueAccessToken, issueRefreshToken, resolveAccessToken } from "@/lib/tokens/token-service";
import { RefreshToken } from "@/models/RefreshToken";
import { createTestClient, createTestUser } from "./helpers";

const CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
const IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1";

describe("where a session was signed in", () => {
  it("reads the hosting edge's location headers", () => {
    const at = (headers: Record<string, string>) => placeFromRequest(new Request("http://localhost/", { headers }));
    expect(at({ "x-vercel-ip-city": "Navi%20Mumbai", "x-vercel-ip-country": "IN" })).toBe("Navi Mumbai, IN");
    expect(at({ "cf-ipcountry": "GB" })).toBe("GB");
    expect(at({ "cf-ipcountry": "XX" })).toBeNull();
    expect(at({})).toBeNull();
  });
});

describe("devices and sessions", () => {
  async function setup() {
    const { user } = await createTestUser();
    const id = String(user._id);
    const here = await createSession({ userId: id, userAgent: CHROME, ipAddress: "203.0.113.7", place: "Pune, IN", methods: ["password"] });
    const phone = await createSession({ userId: id, userAgent: IPHONE, ipAddress: "198.51.100.4", methods: ["google", "passkey"] });
    const laptop = await createSession({ userId: id, userAgent: CHROME, methods: ["password"] });
    return { user, id, here, phone, laptop };
  }

  it("lists every signed-in device, this one first, with the apps it opened", async () => {
    const { id, here, phone } = await setup();
    const { client } = await createTestClient();
    await issueRefreshToken({ clientId: client.clientId, userId: id, sessionId: phone.session._id, scope: "openid" });
    const stranger = await createTestUser({ email: "other@example.com" });
    await createSession({ userId: String(stranger.user._id), userAgent: CHROME });

    const sessions = await listDeviceSessions(id, String(here.session._id));
    expect(sessions).toHaveLength(3);
    expect(sessions[0]).toMatchObject({ id: String(here.session._id), current: true, device: "Chrome on Windows", place: "Pune, IN", ipAddress: "203.0.113.7", how: "Signed in with password" });
    expect(sessions.find((s) => s.id === String(phone.session._id))).toMatchObject({ device: "Safari on iPhone", apps: [{ clientId: client.clientId, name: "Test App", signedIn: true }], how: "Signed in with Google and a passkey" });
  });

  it("signs out one or several, ending the app sign-ins made through them", async () => {
    const { id, here, phone, laptop } = await setup();
    const { client } = await createTestClient();
    const access = await issueAccessToken({ clientId: client.clientId, userId: id, sessionId: phone.session._id, scope: "openid" });
    await issueRefreshToken({ clientId: client.clientId, userId: id, sessionId: phone.session._id, scope: "openid" });

    expect(await signOutSessions(id, [String(phone.session._id)], String(here.session._id))).toEqual({ count: 1, includingThisOne: false });
    expect(await validateSession(phone.token)).toBeNull();
    expect(await resolveAccessToken(access.token)).toBeNull();
    expect(await RefreshToken.countDocuments({ sessionId: phone.session._id, revokedAt: null })).toBe(0);
    expect(await validateSession(laptop.token)).not.toBeNull();

    // Choosing this one too signs it out.
    expect(await signOutSessions(id, [String(laptop.session._id), String(here.session._id)], String(here.session._id))).toEqual({ count: 2, includingThisOne: true });
  });

  it("signs out everywhere but here, and leaves other accounts' sessions alone", async () => {
    const { id, here, phone, laptop } = await setup();
    const stranger = await createTestUser({ email: "other@example.com" });
    const theirs = await createSession({ userId: String(stranger.user._id) });
    // Someone else's session id, slipped in, is ignored.
    expect(await signOutSessions(id, [String(theirs.session._id)], String(here.session._id))).toEqual({ count: 0, includingThisOne: false });
    expect(await signOutOtherSessions(id, String(here.session._id))).toEqual({ count: 2, includingThisOne: false });
    expect(await validateSession(here.token)).not.toBeNull();
    expect(await validateSession(phone.token)).toBeNull();
    expect(await validateSession(laptop.token)).toBeNull();
    expect(await validateSession(theirs.token)).not.toBeNull();
  });

  it("signs one app out on one device, leaving Identity and other apps signed in", async () => {
    const { id, here, phone } = await setup();
    const { client: crm } = await createTestClient();
    const { client: docs } = await createTestClient();
    await OAuthClient.updateOne({ _id: docs._id }, { $set: { name: "Docs" } });
    const crmPhone = await issueAccessToken({ clientId: crm.clientId, userId: id, sessionId: phone.session._id, scope: "openid" });
    await issueRefreshToken({ clientId: crm.clientId, userId: id, sessionId: phone.session._id, scope: "openid" });
    const crmHere = await issueAccessToken({ clientId: crm.clientId, userId: id, sessionId: here.session._id, scope: "openid" });
    const docsPhone = await issueAccessToken({ clientId: docs.clientId, userId: id, sessionId: phone.session._id, scope: "openid" });

    expect(await signOutOfApp(id, crm.clientId, String(phone.session._id))).toEqual({ ended: 2 });
    expect(await resolveAccessToken(crmPhone.token)).toBeNull();
    expect(await RefreshToken.countDocuments({ sessionId: phone.session._id, clientId: crm.clientId, revokedAt: null })).toBe(0);
    expect(await resolveAccessToken(crmHere.token)).not.toBeNull();
    expect(await resolveAccessToken(docsPhone.token)).not.toBeNull();
    expect(await validateSession(phone.token)).not.toBeNull();

    // The device still remembers the app, now signed out.
    const phoneView = (await listDeviceSessions(id, String(here.session._id))).find((s) => s.id === String(phone.session._id));
    expect(phoneView?.apps).toEqual([
      { clientId: docs.clientId, name: "Docs", signedIn: true },
      { clientId: crm.clientId, name: "Test App", signedIn: false },
    ]);
    expect(await IdentityEvent.countDocuments({ action: "auth.app_signed_out", clientId: crm.clientId })).toBe(1);
  });

  it("signs one app out on every device, and won't touch another account's session", async () => {
    const { id, here, phone } = await setup();
    const { client } = await createTestClient();
    const a = await issueAccessToken({ clientId: client.clientId, userId: id, sessionId: phone.session._id, scope: "openid" });
    const b = await issueAccessToken({ clientId: client.clientId, userId: id, sessionId: here.session._id, scope: "openid" });
    const stranger = await createTestUser({ email: "other@example.com" });
    const theirs = await createSession({ userId: String(stranger.user._id) });
    const theirToken = await issueAccessToken({ clientId: client.clientId, userId: String(stranger.user._id), sessionId: theirs.session._id, scope: "openid" });

    await expect(signOutOfApp(id, client.clientId, String(theirs.session._id))).rejects.toMatchObject({ status: 404 });
    expect(await signOutOfApp(id, client.clientId, null)).toEqual({ ended: 2 });
    expect(await resolveAccessToken(a.token)).toBeNull();
    expect(await resolveAccessToken(b.token)).toBeNull();
    expect(await resolveAccessToken(theirToken.token)).not.toBeNull();
    // Nothing left to end: no second event.
    expect(await signOutOfApp(id, client.clientId, null)).toEqual({ ended: 0 });
    expect(await IdentityEvent.countDocuments({ action: "auth.app_signed_out" })).toBe(1);
  });
});
