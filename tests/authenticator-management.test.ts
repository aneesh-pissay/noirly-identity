import { generate } from "otplib";
import { describe, expect, it } from "vitest";
import { assertKeepsSecondFactor, factorCount, factorCounts, isMfaRequired } from "@/lib/security/factors";
import { beginTotp, confirmTotp, RECOVERY_CODE_COUNT, remindRecoveryCodesLow, replaceRecoveryCodes, verifyTotpOrRecovery } from "@/lib/security/mfa";
import { resetEmailProvider, setEmailProvider, type EmailMessage } from "@/lib/email/email-service";
import { Mfa, Passkey } from "@/models/SecurityCredential";
import { User } from "@/models/User";
import { createTestUser } from "./helpers";

describe("second factors", () => {
  it("count the authenticator app and every key, second-step-only keys included", async () => {
    const { user } = await createTestUser();
    await Mfa.create({ userId: user._id, enabled: true, secret: "x" });
    await Passkey.create({ userId: user._id, credentialId: "a", publicKey: "k", counter: 0 });
    await Passkey.create({ userId: user._id, credentialId: "b", publicKey: "k", counter: 0, kind: "security_key", standalone: false });
    const counts = await factorCounts(user._id);
    expect(counts).toEqual({ totp: true, keys: 2 });
    expect(factorCount(counts)).toBe(3);
  });

  it("can all be removed when no second step is required", async () => {
    const { user } = await createTestUser();
    await Passkey.create({ userId: user._id, credentialId: "only", publicKey: "k", counter: 0 });
    expect(await isMfaRequired(user._id)).toBe(false);
    await expect(assertKeepsSecondFactor(String(user._id), { keys: 1 })).resolves.toBeUndefined();
  });

  it("keep the last one while a second step is required", async () => {
    const { user } = await createTestUser();
    await User.updateOne({ _id: user._id }, { $set: { mfaRequired: true } });
    await Mfa.create({ userId: user._id, enabled: true, secret: "x" });
    await Passkey.create({ userId: user._id, credentialId: "k1", publicKey: "k", counter: 0 });
    // Two factors: either can go.
    await expect(assertKeepsSecondFactor(String(user._id), { totp: true })).resolves.toBeUndefined();
    await expect(assertKeepsSecondFactor(String(user._id), { keys: 1 })).resolves.toBeUndefined();
    await Passkey.deleteMany({ userId: user._id });
    // One left: it stays.
    await expect(assertKeepsSecondFactor(String(user._id), { totp: true })).rejects.toMatchObject({ code: "last_second_factor" });
  });
});

describe("authenticator app dates", () => {
  it("records when it was set up and last used", async () => {
    const { user } = await createTestUser();
    const id = String(user._id);
    const { secret } = await beginTotp(id, user.email);
    const recovery = await confirmTotp(id, await generate({ secret }));
    const enabled = await Mfa.findOne({ userId: user._id }).lean();
    expect(enabled!.enabledAt).toBeInstanceOf(Date);
    expect(enabled!.lastUsedAt).toBeNull();
    expect(await verifyTotpOrRecovery(id, recovery[0]!)).toBe("recovery_code");
    expect((await Mfa.findOne({ userId: user._id }).lean())!.lastUsedAt).toBeInstanceOf(Date);
  });
});

describe("recovery codes", () => {
  it("are replaced with a new set, and the old ones stop working", async () => {
    const { user } = await createTestUser();
    const id = String(user._id);
    const { secret } = await beginTotp(id, user.email);
    const old = await confirmTotp(id, await generate({ secret }));
    const fresh = await replaceRecoveryCodes(id);
    expect(fresh).toHaveLength(RECOVERY_CODE_COUNT);
    expect(fresh.some((code) => old.includes(code))).toBe(false);
    await expect(verifyTotpOrRecovery(id, old[0]!)).rejects.toMatchObject({ code: "invalid_code" });
    await expect(verifyTotpOrRecovery(id, fresh[0]!)).resolves.toBe("recovery_code");
  });

  it("can't be made without an authenticator app", async () => {
    const { user } = await createTestUser();
    await expect(replaceRecoveryCodes(String(user._id))).rejects.toMatchObject({ code: "totp_not_enabled" });
  });

  it("send a reminder when few are left", async () => {
    const sent: EmailMessage[] = [];
    setEmailProvider({ send: async (message) => { sent.push(message); } });
    try {
      await remindRecoveryCodesLow("asha@example.com", 2);
      await remindRecoveryCodesLow("asha@example.com", 0);
      expect(sent.map((m) => m.to)).toEqual(["asha@example.com", "asha@example.com"]);
      expect(sent[0]!.text).toContain("only 2 recovery codes left");
      expect(sent[1]!.text).toContain("no recovery codes left");
      expect(sent[0]!.text).toContain("/account#security-title");
    } finally {
      resetEmailProvider();
    }
  });
});

describe("authenticator setup", () => {
  it("draws the QR code itself, from the same otpauth link as the setup key", async () => {
    const { user } = await createTestUser();
    const { secret, uri, qrSvg } = await beginTotp(String(user._id), user.email);
    expect(uri).toMatch(/^otpauth:\/\/totp\/Noirly%20Identity:.+\?.*secret=/);
    expect(uri).toContain(`secret=${secret}`);
    expect(qrSvg.startsWith("data:image/svg+xml;base64,")).toBe(true);
    const svg = Buffer.from(qrSvg.split(",")[1]!, "base64").toString("utf8");
    expect(svg).toContain("<svg");
    expect(svg).toContain("<path");
    // The secret itself isn't in the image as text: it's in the QR modules.
    expect(svg).not.toContain(secret);
  });
});
