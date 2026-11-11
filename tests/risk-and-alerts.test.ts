import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { POST as mfaRoute, GET as mfaKind } from "@/app/api/auth/mfa/route";
import { loginUser } from "@/lib/auth/auth-service";
import { recordEvent } from "@/lib/audit/event-log";
import { resetEmailProvider, setEmailProvider, type EmailMessage } from "@/lib/email/email-service";
import { assessSignInRisk, countryOf, noteSignIn } from "@/lib/security/risk";
import { SignInRecord } from "@/models/SignInRecord";
import { IdentityEvent } from "@/models/IdentityEvent";
import { getEnv } from "@/lib/config/env";
import { createTestUser } from "./helpers";

const jar = vi.hoisted(() => new Map<string, string>());
vi.mock("next/headers", () => ({ cookies: async () => ({ get: (key: string) => (jar.has(key) ? { value: jar.get(key) } : undefined) }) }));

let sent: EmailMessage[] = [];
beforeEach(() => {
  jar.clear();
  sent = [];
  setEmailProvider({ send: async (m) => { sent.push(m); } });
});
afterEach(() => resetEmailProvider());

const HOUR = 3600_000;
const home = { deviceId: "laptop-device-00000001", userAgent: "Mozilla/5.0 (Windows NT 10.0) Chrome/141.0", place: "Mumbai, IN" };

describe("unusual sign-in detection", () => {
  it("finds nothing unusual on a new account, then spots a new device, a new country and impossible travel", async () => {
    const { user } = await createTestUser();
    expect(await noteSignIn(user._id, { ...home, at: new Date(Date.now() - 48 * HOUR) })).toEqual({ level: "none", signals: [] });
    expect(await assessSignInRisk(user._id, home)).toEqual({ level: "none", signals: [] });
    expect(await assessSignInRisk(user._id, { ...home, deviceId: "phone-device-000000002" })).toEqual({ level: "low", signals: ["new_device"] });
    expect(await assessSignInRisk(user._id, { ...home, place: "London, GB" })).toEqual({ level: "medium", signals: ["new_country"] });
    expect(await assessSignInRisk(user._id, { deviceId: "unknown-device-00000003", place: "Lagos, NG" })).toEqual({ level: "high", signals: ["new_device", "new_country"] });

    // An hour after a sign-in from India, one from Britain.
    await noteSignIn(user._id, { ...home, at: new Date(Date.now() - HOUR) });
    const travel = await assessSignInRisk(user._id, { ...home, place: "London, GB" });
    expect(travel).toMatchObject({ level: "high" });
    expect(travel.signals).toContain("impossible_travel");
    expect(countryOf("Navi Mumbai, IN")).toBe("IN");
    expect(countryOf(null)).toBeNull();
  });

  it("logs an unusual sign-in and tells the owner by email", async () => {
    const { user } = await createTestUser();
    await noteSignIn(user._id, { ...home, at: new Date(Date.now() - 48 * HOUR) });
    await noteSignIn(user._id, { deviceId: "stranger-device-0000001", place: "Lagos, NG" });
    expect(await SignInRecord.countDocuments({ userId: user._id })).toBe(2);
    expect(await IdentityEvent.findOne({ action: "auth.unusual_sign_in" }).lean()).toMatchObject({ data: { level: "high", signals: ["new_device", "new_country"] } });
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({ to: user.email, subject: "New sign-in to your Noirly account" });
  });
});

describe("adaptive second step", () => {
  it("emails a code to an account without a second step when a sign-in is risky, and accepts only that code", async () => {
    const { user, password } = await createTestUser();
    await noteSignIn(user._id, { ...home, at: new Date(Date.now() - 48 * HOUR) });
    // From home: straight in.
    await expect(loginUser({ email: user.email, password } as never, { ...home, ipAddress: "203.0.113.1" })).resolves.toBeTruthy();

    // From a new device in a new country: a code, by email.
    let challenge = "";
    try {
      await loginUser({ email: user.email, password } as never, { deviceId: "stranger-device-0000001", place: "Lagos, NG", ipAddress: "198.51.100.1", userAgent: null });
    } catch (error) {
      expect(error).toMatchObject({ code: "mfa_required" });
      challenge = (error as { details: { challenge: string } }).details.challenge;
    }
    expect(challenge).toBeTruthy();
    const email = sent.find((m) => m.subject.startsWith("Your Noirly sign-in code"))!;
    const code = /(\d{6})/.exec(email.subject)![1]!;

    jar.set(getEnv().CSRF_COOKIE_NAME, "csrf");
    const cookieHeaders = { cookie: `noirly_mfa_challenge=${challenge}; ${getEnv().CSRF_COOKIE_NAME}=csrf`, "x-csrf-token": "csrf", origin: "http://localhost:3000", "content-type": "application/json" };
    expect(await (await mfaKind(new NextRequest("http://localhost:3000/api/auth/mfa", { headers: { cookie: `noirly_mfa_challenge=${challenge}` } }))).json()).toEqual({ via: "email" });
    const wrong = await mfaRoute(new NextRequest("http://localhost:3000/api/auth/mfa", { method: "POST", headers: cookieHeaders, body: JSON.stringify({ action: "code", code: code === "000000" ? "111111" : "000000" }) }));
    expect(wrong.status).toBe(400);
    const right = await mfaRoute(new NextRequest("http://localhost:3000/api/auth/mfa", { method: "POST", headers: cookieHeaders, body: JSON.stringify({ action: "code", code }) }));
    expect(right.status).toBe(200);
    expect((await IdentityEvent.find({ action: "auth.signed_in" }).sort({ seq: -1 }).lean())[0]?.data).toMatchObject({ methods: ["password", "email_code"] });
  });
});

describe("security alerts", () => {
  it("email the owner when a factor or password changes, and not for everyday things", async () => {
    const { user } = await createTestUser();
    await recordEvent({ action: "passkey.added", subjectId: user._id });
    await recordEvent({ action: "password.changed", subjectId: user._id });
    await recordEvent({ action: "email.added", subjectId: user._id, data: { email: "second@example.com" } });
    await recordEvent({ action: "account.profile_updated", subjectId: user._id, data: { fields: ["firstName"] } });
    expect(sent.map((m) => m.subject)).toEqual(["Passkey added", "Password changed", "Email address added"]);
    expect(sent.every((m) => m.to === user.email)).toBe(true);
  });
});
