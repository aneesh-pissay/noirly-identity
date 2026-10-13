import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { generateSecret, verify, generateURI } from "otplib";
import { AppError } from "@/lib/api/errors";
import { getEnv } from "@/lib/config/env";
import { generateSecureToken, hashToken } from "@/lib/security/crypto";
import { consumeRateLimit } from "@/lib/security/shared-rate-limit";
import { Mfa, Passkey, SecurityChallenge } from "@/models/SecurityCredential";

export const MFA_COOKIE = "noirly_mfa_challenge";
export type MobileMfaContext = { clientId: string; scope: string; nonce?: string };

function encryptionKey() { return createHash("sha256").update(getEnv().ENCRYPTION_KEY).digest(); }
function encrypt(secret: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const body = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString("base64url");
}
function decrypt(value: string): string {
  const data = Buffer.from(value, "base64url");
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey(), data.subarray(0, 12));
  decipher.setAuthTag(data.subarray(12, 28));
  return Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]).toString("utf8");
}

export async function newChallenge(input: { userId?: string; purpose: string; challenge?: string; sessionId?: string } & Partial<MobileMfaContext>) {
  const token = generateSecureToken();
  await SecurityChallenge.create({ ...input, tokenHash: hashToken(token), expiresAt: new Date(Date.now() + 5 * 60_000) });
  return token;
}

/** Called after the primary factor and before issuing any session or tokens. */
export async function requireSecondFactor(userId: string, mobile?: MobileMfaContext): Promise<void> {
  const [mfa, passkey] = await Promise.all([Mfa.findOne({ userId, enabled: true }).lean(), Passkey.exists({ userId })]);
  if (!mfa && !passkey) return;
  const challenge = await newChallenge({ userId, purpose: "login-mfa", ...mobile });
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
  return { secret, uri: generateURI({ issuer: "Noirly Identity", label: email, secret }) };
}

export async function confirmTotp(userId: string, code: string) {
  await checkFactorRate(userId);
  const record = await Mfa.findOne({ userId, enabled: false, pendingExpiresAt: { $gt: new Date() } }).lean();
  if (!record?.pendingSecret) throw new AppError("Enrollment expired. Start again.", 400, "invalid_enrollment");
  if (!/^\d{6}$/.test(code)) throw new AppError("Enter a six-digit code", 400, "invalid_code");
  const epoch = Math.floor(Date.now() / 1000);
  const result = await verify({ strategy: "totp", secret: decrypt(record.pendingSecret), token: code, epochTolerance: 30, epoch });
  if (!result.valid) throw new AppError("Invalid authenticator code", 400, "invalid_code");
  const codes = Array.from({ length: 10 }, () => randomBytes(10).toString("hex"));
  const updated = await Mfa.updateOne({ _id: record._id, enabled: false, pendingSecret: record.pendingSecret }, { $set: {
    enabled: true, secret: record.pendingSecret, pendingSecret: null, pendingExpiresAt: null,
    lastStep: Math.floor(epoch / 30) + result.delta, recoveryHashes: codes.map(hashToken),
  } });
  if (!updated.modifiedCount) throw new AppError("Enrollment changed. Start again.", 409, "invalid_enrollment");
  return codes;
}

export async function verifyTotpOrRecovery(userId: string, code: string) {
  await checkFactorRate(userId);
  if (/^[a-f0-9]{20}$/i.test(code)) {
    const hash = hashToken(code.toLowerCase());
    const result = await Mfa.updateOne({ userId, enabled: true, recoveryHashes: hash }, { $pull: { recoveryHashes: hash } });
    if (result.modifiedCount === 1) return;
  } else if (/^\d{6}$/.test(code)) {
    const record = await Mfa.findOne({ userId, enabled: true }).lean();
    if (record?.secret) {
      const epoch = Math.floor(Date.now() / 1000);
      const result = await verify({ strategy: "totp", secret: decrypt(record.secret), token: code, epochTolerance: 30, epoch });
      if (result.valid) {
        const step = Math.floor(epoch / 30) + result.delta;
        const used = await Mfa.updateOne({ _id: record._id, enabled: true, lastStep: { $lt: step } }, { $set: { lastStep: step } });
        if (used.modifiedCount === 1) return;
      }
    }
  }
  throw new AppError("Invalid or already used code", 401, "invalid_code");
}
