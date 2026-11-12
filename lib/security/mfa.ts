import { randomBytes, randomInt } from "node:crypto";
import { generateSecret, verify, generateURI } from "otplib";
import QRCode from "qrcode";
import { AppError } from "@/lib/api/errors";
import { getEnv } from "@/lib/config/env";
import { openSecret, sealSecret } from "@/lib/security/encryption";
import type { Risk } from "@/lib/security/risk";
import { User } from "@/models/User";
import { sendEmail } from "@/lib/email/email-service";
import { buildNoticeEmail, buildRecoveryCodesLowEmail } from "@/lib/email/templates";
import { generateSecureToken, hashToken } from "@/lib/security/crypto";
import { consumeRateLimit } from "@/lib/security/shared-rate-limit";
import { Mfa, Passkey, SecurityChallenge } from "@/models/SecurityCredential";
import type { SignInMethod } from "@/lib/audit/chain";

export const MFA_COOKIE = "noirly_mfa_challenge";
export type MobileMfaContext = { clientId: string; scope: string; nonce?: string };

const encrypt = (secret: string) => sealSecret(secret);
const decrypt = (value: string) => openSecret(value);

export async function newChallenge(input: { userId?: string; purpose: string; challenge?: string; sessionId?: string; method?: SignInMethod; stepUpSessionId?: string; priorMethods?: string[] } & Partial<MobileMfaContext>) {
  const token = generateSecureToken();
  await SecurityChallenge.create({ ...input, tokenHash: hashToken(token), expiresAt: new Date(Date.now() + 5 * 60_000) });
  return token;
}

/** Called after the primary factor and before issuing any session or tokens. */
/**
 * A second step at sign-in: always when the account has one; and, when it has
 * none but the sign-in looks risky (lib/security/risk.ts), a code emailed to
 * its address (adaptive MFA).
 */
export async function requireSecondFactor(userId: string, mobile?: MobileMfaContext, method?: SignInMethod, risk?: Risk): Promise<void> {
  const [mfa, passkey] = await Promise.all([Mfa.findOne({ userId, enabled: true }).lean(), Passkey.exists({ userId })]);
  if (!mfa && !passkey) {
    if (risk?.level !== "high") return;
    const code = String(randomInt(0, 1_000_000)).padStart(6, "0");
    const challenge = await newChallenge({ userId, purpose: "login-mfa", method, ...mobile });
    await SecurityChallenge.updateOne({ tokenHash: hashToken(challenge) }, { $set: { emailCodeHash: hashToken(`email-code:${code}`) } });
    const user = await User.findById(userId).select("email").lean();
    if (user) {
      await sendEmail({
        to: user.email,
        ...buildNoticeEmail({
          subject: `Your Noirly sign-in code: ${code}`,
          paragraphs: [
            `Someone is signing in to your account from somewhere new. If it's you, enter this code: ${code}`,
            "It works for 5 minutes. If it isn't you, don't share it: change your password.",
          ],
        }),
        meta: { kind: "risk-code" },
      });
    }
    throw new AppError("We emailed you a code to confirm it's you", 401, "mfa_required", { challenge, mobile: Boolean(mobile) });
  }
  const challenge = await newChallenge({ userId, purpose: "login-mfa", method, ...mobile });
  throw new AppError("Complete verification to sign in", 401, "mfa_required", { challenge, mobile: Boolean(mobile) });
}

export async function checkFactorRate(userId: string) {
  const result = await consumeRateLimit(`mfa:${userId}`, 5, 300);
  if (!result.allowed) throw new AppError("Too many verification attempts. Try again later.", 429, "rate_limited");
}

export async function beginTotp(userId: string, email: string) {
  const existing = await Mfa.findOne({ userId }).lean();
  if (existing?.enabled) throw new AppError("Authenticator already enabled", 409, "already_enabled");
  const secret = generateSecret();
  await Mfa.findOneAndUpdate({ userId, enabled: { $ne: true } }, {
    $set: { pendingSecret: encrypt(secret), pendingExpiresAt: new Date(Date.now() + 10 * 60_000) },
  }, { upsert: true });
  const uri = generateURI({ issuer: "Noirly Identity", label: email, secret });
  // Drawn here, not by a QR service: the image carries the secret.
  const qr = await QRCode.toString(uri, { type: "svg", errorCorrectionLevel: "M", margin: 2, color: { dark: "#000000", light: "#ffffff" } });
  return { secret, uri, qrSvg: `data:image/svg+xml;base64,${Buffer.from(qr).toString("base64")}` };
}

export async function confirmTotp(userId: string, code: string) {
  await checkFactorRate(userId);
  const record = await Mfa.findOne({ userId, enabled: false, pendingExpiresAt: { $gt: new Date() } }).lean();
  if (!record?.pendingSecret) throw new AppError("Enrollment expired. Start again.", 400, "invalid_enrollment");
  if (!/^\d{6}$/.test(code)) throw new AppError("Enter a six-digit code", 400, "invalid_code");
  const epoch = Math.floor(Date.now() / 1000);
  const result = await verify({ strategy: "totp", secret: decrypt(record.pendingSecret), token: code, epochTolerance: 30, epoch });
  if (!result.valid) throw new AppError("Invalid authenticator code", 400, "invalid_code");
  const codes = newRecoveryCodes();
  const updated = await Mfa.updateOne({ _id: record._id, enabled: false, pendingSecret: record.pendingSecret }, { $set: {
    enabled: true, secret: record.pendingSecret, pendingSecret: null, pendingExpiresAt: null,
    lastStep: Math.floor(epoch / 30) + result.delta, recoveryHashes: codes.map(hashToken), enabledAt: new Date(),
  } });
  if (!updated.modifiedCount) throw new AppError("Enrollment changed. Start again.", 409, "invalid_enrollment");
  return codes;
}

/** Checks an authenticator or recovery code and says which it was. */
/** How many recovery codes a set has, and how few left prompts a reminder to replace them. */
export const RECOVERY_CODE_COUNT = 10;
export const RECOVERY_CODES_LOW = 3;

function newRecoveryCodes(): string[] {
  return Array.from({ length: RECOVERY_CODE_COUNT }, () => randomBytes(10).toString("hex"));
}

/** Emails a reminder to make new recovery codes; never fails the sign-in that prompted it. */
export async function remindRecoveryCodesLow(email: string, remaining: number) {
  try {
    const message = buildRecoveryCodesLowEmail({ remaining, accountUrl: `${getEnv().APP_URL}/account#security-title` });
    await sendEmail({ to: email, subject: message.subject, text: message.text, html: message.html, meta: { kind: "recovery_codes_low" } });
  } catch (error) {
    console.error("Recovery code reminder not sent:", error instanceof Error ? error.message : error);
  }
}

/** A fresh set of recovery codes; every code from the old set stops working at once. */
export async function replaceRecoveryCodes(userId: string): Promise<string[]> {
  const codes = newRecoveryCodes();
  const updated = await Mfa.updateOne({ userId, enabled: true }, { $set: { recoveryHashes: codes.map(hashToken) } });
  if (updated.matchedCount !== 1) throw new AppError("Set up an authenticator app first: recovery codes come with it.", 400, "totp_not_enabled");
  return codes;
}

export async function verifyTotpOrRecovery(userId: string, code: string): Promise<"totp" | "recovery_code"> {
  await checkFactorRate(userId);
  if (/^[a-f0-9]{20}$/i.test(code)) {
    const hash = hashToken(code.toLowerCase());
    const result = await Mfa.updateOne({ userId, enabled: true, recoveryHashes: hash }, { $pull: { recoveryHashes: hash }, $set: { lastUsedAt: new Date() } });
    if (result.modifiedCount === 1) return "recovery_code";
  } else if (/^\d{6}$/.test(code)) {
    const record = await Mfa.findOne({ userId, enabled: true }).lean();
    if (record?.secret) {
      const epoch = Math.floor(Date.now() / 1000);
      const result = await verify({ strategy: "totp", secret: decrypt(record.secret), token: code, epochTolerance: 30, epoch });
      if (result.valid) {
        const step = Math.floor(epoch / 30) + result.delta;
        const used = await Mfa.updateOne({ _id: record._id, enabled: true, lastStep: { $lt: step } }, { $set: { lastStep: step, lastUsedAt: new Date() } });
        if (used.modifiedCount === 1) return "totp";
      }
    }
  }
  throw new AppError("Invalid or already used code", 401, "invalid_code");
}
