import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { recordEvent, type RequestMeta } from "@/lib/audit/event-log";
import { emailCodeHash, emailCodeMatches, isEmailCode, MAX_CODE_ATTEMPTS, newEmailCode } from "@/lib/security/email-code";
import { consumeRateLimit } from "@/lib/security/shared-rate-limit";
import { isSmsAvailable, sendSms } from "@/lib/sms/sms-service";
import { PhoneVerification } from "@/models/PhoneVerification";
import { User } from "@/models/User";

/**
 * An optional, verified phone number: proved by a code texted to it. It is
 * never a way to sign in, and never the only thing standing between someone
 * and an account: SIM swaps and number recycling make a phone too easy to
 * take over for that. Later it can be a recovery channel alongside others.
 */

export const PHONE_CODE_MINUTES = 10;
/** Texts one account can have sent in an hour, and one number can receive. */
const TEXTS_PER_HOUR = 3;

/**
 * "+91 98765 43210", "+1 (415) 555-0100" → "+919876543210": an
 * international (E.164) number, country code included, or null.
 */
export function normalizePhone(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed.startsWith("+")) return null;
  const digits = trimmed.slice(1).replace(/[\s().-]/g, "");
  return /^[1-9]\d{7,14}$/.test(digits) ? `+${digits}` : null;
}

/** "+919876543210" → "+91 •••• ••3210", for showing which number a code went to. */
export function maskPhone(phone: string): string {
  return `${phone.slice(0, 3)} •••• ••${phone.slice(-4)}`;
}

function oid(id: string) {
  if (!Types.ObjectId.isValid(id)) throw new AppError("Invalid account", 400, "invalid_request");
  return new Types.ObjectId(id);
}

export type PhoneState = { available: boolean; phone: string | null; verified: boolean; pending: string | null };

export async function phoneState(userId: string): Promise<PhoneState> {
  const user = await User.findById(oid(userId)).select("phoneNumber phoneVerifiedAt").lean();
  if (!user) throw new AppError("Authentication required", 401, "unauthorized");
  const pending = await PhoneVerification.findOne({ userId: user._id, usedAt: null, expiresAt: { $gt: new Date() } }).sort({ createdAt: -1 }).lean();
  return { available: isSmsAvailable(), phone: user.phoneNumber ?? null, verified: Boolean(user.phoneNumber && user.phoneVerifiedAt), pending: pending ? maskPhone(pending.phone) : null };
}

/** Texts a six-digit code to a number. Nothing on the account changes until the code comes back. */
export async function startPhoneVerification(userId: string, rawPhone: string, meta: RequestMeta = {}) {
  if (!isSmsAvailable()) throw new AppError("Phone verification isn't available here", 501, "sms_not_configured");
  const phone = normalizePhone(rawPhone);
  if (!phone) throw new AppError("Enter the number with its country code, such as +91 98765 43210", 400, "invalid_phone");
  const id = oid(userId);
  for (const key of [`sms-user:${userId}`, `sms-phone:${phone}`]) {
    const limited = await consumeRateLimit(key, TEXTS_PER_HOUR, 3600);
    if (!limited.allowed) throw new AppError("Too many codes sent. Try again later.", 429, "rate_limited", { retryAfterSeconds: limited.retryAfterSeconds });
  }
  // One code at a time.
  await PhoneVerification.updateMany({ userId: id, usedAt: null }, { $set: { usedAt: new Date() } });
  const code = newEmailCode();
  const recordId = new Types.ObjectId();
  await PhoneVerification.create({ _id: recordId, userId: id, phone, codeHash: emailCodeHash(`phone:${recordId}`, code), expiresAt: new Date(Date.now() + PHONE_CODE_MINUTES * 60_000) });
  await sendSms({ to: phone, body: `${code} is your Noirly verification code. It works for ${PHONE_CODE_MINUTES} minutes. Don't share it.`, kind: "phone_verification" });
  await recordEvent({ action: "phone.verification_sent", subjectId: id, request: meta, data: { phone: maskPhone(phone) } });
  return phoneState(userId);
}

/** The texted code, typed back: the number becomes the account's, verified. Five wrong tries end that code. */
export async function confirmPhoneVerification(userId: string, rawCode: string, meta: RequestMeta = {}) {
  const id = oid(userId);
  const code = rawCode.replace(/\s+/g, "");
  const record = await PhoneVerification.findOne({ userId: id, usedAt: null, expiresAt: { $gt: new Date() } }).sort({ createdAt: -1 });
  if (!record || !isEmailCode(code)) throw new AppError("That code isn't right, or it has expired. Send a new one.", 400, "invalid_code");
  if (!emailCodeMatches(`phone:${record._id}`, code, record.codeHash)) {
    record.attempts += 1;
    if (record.attempts >= MAX_CODE_ATTEMPTS) record.usedAt = new Date();
    await record.save();
    throw new AppError("That code isn't right, or it has expired. Send a new one.", 400, "invalid_code");
  }
  const claimed = await PhoneVerification.updateOne({ _id: record._id, usedAt: null }, { $set: { usedAt: new Date() } });
  if (claimed.modifiedCount !== 1) throw new AppError("That code was already used", 400, "invalid_code");
  await User.updateOne({ _id: id }, { $set: { phoneNumber: record.phone, phoneVerifiedAt: new Date() } });
  await recordEvent({ action: "phone.verified", subjectId: id, request: meta, data: { phone: maskPhone(record.phone) } });
  return phoneState(userId);
}

export async function removePhone(userId: string, meta: RequestMeta = {}) {
  const id = oid(userId);
  const user = await User.findById(id).select("phoneNumber").lean();
  await User.updateOne({ _id: id }, { $set: { phoneNumber: null, phoneVerifiedAt: null } });
  await PhoneVerification.updateMany({ userId: id, usedAt: null }, { $set: { usedAt: new Date() } });
  if (user?.phoneNumber) await recordEvent({ action: "phone.removed", subjectId: id, request: meta, data: { phone: maskPhone(user.phoneNumber) } });
  return phoneState(userId);
}
