import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { listSignInMethods } from "@/lib/account/identities";
import { confirmPhoneVerification, maskPhone, normalizePhone, phoneState, removePhone, startPhoneVerification } from "@/lib/account/phone";
import { listEvents } from "@/lib/audit/event-log";
import { updateUserProfile } from "@/lib/auth/auth-service";
import { resetEnvCache } from "@/lib/config/env";
import { setSmsProvider, smsMode, type SmsMessage } from "@/lib/sms/sms-service";
import { updateProfileSchema } from "@/lib/validation/schemas";
import { User } from "@/models/User";
import { createAuthedSession, createTestUser } from "./helpers";

let texts: SmsMessage[] = [];

beforeEach(() => {
  texts = [];
  setSmsProvider({ send: async (message) => { texts.push(message); } });
});

afterEach(() => {
  setSmsProvider(null);
  delete process.env.SMS_PROVIDER;
  resetEnvCache();
});

const codeIn = (message: SmsMessage) => message.body.match(/^(\d{6})/)![1]!;

describe("phone numbers", () => {
  it("take international numbers with their country code", () => {
    expect(normalizePhone("+91 98765 43210")).toBe("+919876543210");
    expect(normalizePhone("+1 (415) 555-0100")).toBe("+14155550100");
    expect(normalizePhone("98765 43210")).toBeNull();
    expect(normalizePhone("+0123456789")).toBeNull();
    expect(maskPhone("+919876543210")).toBe("+91 •••• ••3210");
  });

  it("send nothing in production unless a provider is set up", () => {
    setSmsProvider(null);
    process.env.SMS_PROVIDER = "twilio";
    resetEnvCache();
    // Twilio named but not configured: no texts.
    expect(smsMode()).toBe("none");
  });
});

describe("phone verification", () => {
  it("verifies a number with a texted code, and can remove it", async () => {
    const { user } = await createTestUser();
    const id = String(user._id);
    const pending = await startPhoneVerification(id, "+91 98765 43210", { ipAddress: "203.0.113.7" });
    expect(pending).toMatchObject({ phone: null, verified: false, pending: "+91 •••• ••3210" });
    expect(texts).toEqual([expect.objectContaining({ to: "+919876543210", kind: "phone_verification" })]);

    const verified = await confirmPhoneVerification(id, codeIn(texts[0]!));
    expect(verified).toMatchObject({ phone: "+919876543210", verified: true, pending: null });
    // It's not a way in: sign-in methods don't count it.
    const methods = await listSignInMethods(id);
    expect(methods).not.toHaveProperty("phone");

    expect(await removePhone(id)).toMatchObject({ phone: null, verified: false });
    const actions = (await listEvents({ stream: `user:${id}` })).events.map((e) => [e.action, e.data]);
    expect(actions).toEqual([
      ["phone.removed", { phone: "+91 •••• ••3210" }],
      ["phone.verified", { phone: "+91 •••• ••3210" }],
      ["phone.verification_sent", { phone: "+91 •••• ••3210" }],
    ]);
  });

  it("ends a code after five wrong tries, and limits how many texts go out", async () => {
    const { user } = await createTestUser();
    const id = String(user._id);
    await startPhoneVerification(id, "+14155550100");
    const code = codeIn(texts[0]!);
    const wrong = code === "000000" ? "111111" : "000000";
    for (let i = 0; i < 5; i++) await expect(confirmPhoneVerification(id, wrong)).rejects.toMatchObject({ code: "invalid_code" });
    await expect(confirmPhoneVerification(id, code)).rejects.toMatchObject({ code: "invalid_code" });
    await startPhoneVerification(id, "+14155550100");
    await startPhoneVerification(id, "+14155550100");
    await expect(startPhoneVerification(id, "+14155550100")).rejects.toMatchObject({ code: "rate_limited" });
    expect(texts).toHaveLength(3);
  });

  it("forgets the verification when the number is changed by hand", async () => {
    const { user } = await createTestUser();
    const id = String(user._id);
    await startPhoneVerification(id, "+919876543210");
    await confirmPhoneVerification(id, codeIn(texts[0]!));
    const { token } = await createAuthedSession(id);
    const updated = await updateUserProfile(token, updateProfileSchema.parse({ phoneNumber: "+919999999999" }));
    expect(updated).toMatchObject({ phoneNumber: "+919999999999", phoneVerified: false });
    expect((await User.findById(id).lean())!.phoneVerifiedAt).toBeNull();
    expect(await phoneState(id)).toMatchObject({ verified: false });
  });
});
