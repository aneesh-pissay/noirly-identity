import { describe, expect, it } from "vitest";
import { describeActivity, deviceLabel, newDeviceSignIns } from "@/lib/audit/activity";
import { listActivity } from "@/lib/audit/activity-service";
import { recordEvent } from "@/lib/audit/event-log";
import { createTestClient, createTestUser } from "./helpers";

const CHROME_WINDOWS = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
const SAFARI_IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1";

describe("activity wording and devices", () => {
  it("names devices well enough to recognise them", () => {
    expect(deviceLabel(CHROME_WINDOWS)).toBe("Chrome on Windows");
    expect(deviceLabel(SAFARI_IPHONE)).toBe("Safari on iPhone");
    expect(deviceLabel("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/141.0 Safari/537.36 Edg/141.0")).toBe("Edge on Windows");
    expect(deviceLabel("Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 Chrome/141.0 Mobile Safari/537.36")).toBe("Chrome on Android");
    expect(deviceLabel("Mozilla/5.0 (Macintosh; Intel Mac OS X 14.6; rv:132.0) Gecko/20100101 Firefox/132.0")).toBe("Firefox on Mac");
    expect(deviceLabel("okhttp/4.12.0")).toBe("Mobile app");
    expect(deviceLabel(null)).toBe("Unknown device");
  });

  it("says what happened in plain words", () => {
    expect(describeActivity("auth.signed_in", { methods: ["password", "totp"] })).toBe("Signed in with password and an authenticator code");
    expect(describeActivity("account.profile_updated", { fields: ["firstName", "phoneNumber"] })).toBe("Changed first name and phone number");
    expect(describeActivity("mfa.recovery_code_used", { remaining: 3 })).toBe("Recovery code used (3 left)");
  });

  it("flags sign-ins from a device not seen before, but not the very first", () => {
    const flagged = newDeviceSignIns([{ seq: 1, device: "Chrome on Windows" }, { seq: 3, device: "Chrome on Windows" }, { seq: 5, device: "Safari on iPhone" }, { seq: 8, device: "Safari on iPhone" }]);
    expect([...flagged]).toEqual([5]);
  });
});

describe("security activity", () => {
  it("reads an account's own history back, newest first, with new devices and app names", async () => {
    const { user } = await createTestUser();
    const { client } = await createTestClient();
    const other = await createTestUser({ email: "other@example.com" });
    const at = (userAgent: string) => ({ ipAddress: "203.0.113.7", userAgent });
    await recordEvent({ action: "auth.signed_in", subjectId: user._id, request: at(CHROME_WINDOWS), data: { methods: ["password"] } });
    await recordEvent({ action: "oauth.consent_granted", subjectId: user._id, clientId: client.clientId, request: at(CHROME_WINDOWS), data: { scope: "openid" } });
    await recordEvent({ action: "auth.sign_in_failed", subjectId: user._id, actorId: null, request: at(SAFARI_IPHONE), data: { reason: "wrong_password" } });
    await recordEvent({ action: "auth.signed_in", subjectId: user._id, request: at(SAFARI_IPHONE), data: { methods: ["google", "passkey"] } });
    await recordEvent({ action: "auth.signed_in", subjectId: other.user._id, request: at(CHROME_WINDOWS) });

    const { events, nextBefore } = await listActivity(String(user._id));
    expect(nextBefore).toBeNull();
    expect(events.map((e) => [e.title, e.newDevice, e.notable])).toEqual([
      ["Signed in with Google and a passkey", true, true],
      ["Someone tried to sign in with the wrong password", false, true],
      ["Allowed an app to use your account", false, false],
      ["Signed in with password", false, false],
    ]);
    expect(events[0]).toMatchObject({ device: "Safari on iPhone", ipAddress: "203.0.113.7", kind: "sign_in" });
    expect(events[2]).toMatchObject({ app: "Test App", kind: "apps" });

    const signIns = await listActivity(String(user._id), { kind: "sign_in" });
    expect(signIns.events).toHaveLength(3);
    await expect(listActivity(String(user._id), { kind: "admin" })).rejects.toMatchObject({ code: "invalid_request" });
  });

  it("pages through a long history", async () => {
    const { user } = await createTestUser();
    for (let i = 0; i < 35; i++) await recordEvent({ action: "auth.signed_out", subjectId: user._id });
    const first = await listActivity(String(user._id));
    expect(first.events).toHaveLength(30);
    expect(first.nextBefore).toBe(6);
    const second = await listActivity(String(user._id), { before: first.nextBefore! });
    expect(second.events.map((e) => e.seq)).toEqual([5, 4, 3, 2, 1]);
    expect(second.nextBefore).toBeNull();
  });
});
