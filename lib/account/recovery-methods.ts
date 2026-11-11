import { randomInt } from "node:crypto";
import { AppError } from "@/lib/api/errors";
import { recordEvent, type RequestMeta } from "@/lib/audit/event-log";
import { normalizeEmail } from "@/lib/auth/user-mapper";
import { sendEmail } from "@/lib/email/email-service";
import { buildNoticeEmail } from "@/lib/email/templates";
import { hashToken } from "@/lib/security/crypto";
import { consumeRateLimit } from "@/lib/security/shared-rate-limit";
import { isSmsAvailable, sendSms } from "@/lib/sms/sms-service";
import { User } from "@/models/User";
import { UserEmail } from "@/models/UserEmail";

/**
 * Verified recovery methods: a recovery email address, and the verified
 * phone. Neither is ever a way to sign in (no password, link or code sign-in
 * goes to them) and apps never see them; they exist to prove it's you when a
 * second step is lost (lib/security/recovery.ts), and to hear about it.
 */

const CODE_MINUTES = 15;

const mask = (email: string) => {
  const [name, domain] = email.split("@");
  return `${name!.slice(0, 1)}***@${domain}`;
};

export async function recoveryMethods(userId: string) {
  const user = await User.findById(userId).select("recoveryEmail recoveryEmailVerifiedAt phoneNumber phoneVerifiedAt").lean();
  if (!user) throw new AppError("Authentication required", 401, "unauthorized");
  return {
    email: user.recoveryEmail && user.recoveryEmailVerifiedAt ? user.recoveryEmail : null,
    pendingEmail: user.recoveryEmail && !user.recoveryEmailVerifiedAt ? user.recoveryEmail : null,
    phone: user.phoneNumber && user.phoneVerifiedAt ? `••• ${user.phoneNumber.slice(-4)}` : null,
  };
}

/** Sends a code to a new recovery address; it counts once confirmed. Not one of the account's own sign-in addresses. */
export async function startRecoveryEmail(userId: string, input: string) {
  const email = normalizeEmail(input);
  const limit = await consumeRateLimit(`recovery-email:${userId}`, 5, 3600);
  if (!limit.allowed) throw new AppError("Too many tries. Try again later.", 429, "rate_limited");
  const user = await User.findById(userId).select("email").lean();
  if (!user) throw new AppError("Authentication required", 401, "unauthorized");
  if (email === user.email || (await UserEmail.exists({ userId, email }))) {
    throw new AppError("Choose an address that isn't one you sign in with: if you lose that one, this should still reach you.", 400, "same_address");
  }
  const code = String(randomInt(0, 1_000_000)).padStart(6, "0");
  await User.updateOne({ _id: userId }, { $set: { recoveryEmail: email, recoveryEmailVerifiedAt: null, recoveryEmailCodeHash: hashToken(`recovery-email:${code}`), recoveryEmailCodeExpiresAt: new Date(Date.now() + CODE_MINUTES * 60_000) } });
  await sendEmail({
    to: email,
    ...buildNoticeEmail({ subject: `Your Noirly recovery address code: ${code}`, paragraphs: [`Enter ${code} to use this address to recover your Noirly account. It works for ${CODE_MINUTES} minutes. This address will never be used to sign in.`] }),
    meta: { kind: "recovery-email-code" },
  });
}

export async function confirmRecoveryEmail(userId: string, code: string, meta: RequestMeta = {}) {
  const user = await User.findById(userId).select("recoveryEmail recoveryEmailCodeHash recoveryEmailCodeExpiresAt").lean();
  if (!user?.recoveryEmail || !user.recoveryEmailCodeHash || !user.recoveryEmailCodeExpiresAt || user.recoveryEmailCodeExpiresAt <= new Date()) {
    throw new AppError("That code has expired. Send a new one.", 400, "invalid_code");
  }
  if (hashToken(`recovery-email:${code.trim()}`) !== user.recoveryEmailCodeHash) throw new AppError("That code isn't right", 400, "invalid_code");
  await User.updateOne({ _id: userId }, { $set: { recoveryEmailVerifiedAt: new Date(), recoveryEmailCodeHash: null, recoveryEmailCodeExpiresAt: null } });
  await recordEvent({ action: "recovery_method.added", subjectId: userId, request: meta, data: { kind: "email", email: mask(user.recoveryEmail) } });
}

export async function removeRecoveryEmail(userId: string, meta: RequestMeta = {}) {
  const user = await User.findById(userId).select("recoveryEmail").lean();
  if (!user?.recoveryEmail) throw new AppError("There's no recovery address", 404, "not_found");
  await User.updateOne({ _id: userId }, { $set: { recoveryEmail: null, recoveryEmailVerifiedAt: null, recoveryEmailCodeHash: null, recoveryEmailCodeExpiresAt: null } });
  await recordEvent({ action: "recovery_method.removed", subjectId: userId, request: meta, data: { kind: "email", email: mask(user.recoveryEmail) } });
}

/** Whether an account has any verified recovery method. */
export async function hasRecoveryMethod(userId: unknown) {
  const user = await User.findById(userId).select("recoveryEmailVerifiedAt phoneVerifiedAt phoneNumber").lean();
  return Boolean(user?.recoveryEmailVerifiedAt || (user?.phoneNumber && user.phoneVerifiedAt));
}

/** Sends a one-time recovery code to every verified recovery method; returns its hash to keep. */
export async function sendRecoveryCode(userId: unknown) {
  const user = await User.findById(userId).select("recoveryEmail recoveryEmailVerifiedAt phoneNumber phoneVerifiedAt").lean();
  if (!user) throw new AppError("Account unavailable", 401, "unauthorized");
  const code = String(randomInt(0, 1_000_000)).padStart(6, "0");
  if (user.recoveryEmail && user.recoveryEmailVerifiedAt) {
    await sendEmail({
      to: user.recoveryEmail,
      ...buildNoticeEmail({ subject: `Your Noirly recovery code: ${code}`, paragraphs: [`Someone is recovering your Noirly account's sign-in. If it's you, enter ${code}. If it isn't, ignore this; the account's owner is being told everywhere.`] }),
      meta: { kind: "recovery-code" },
    }).catch(() => undefined);
  }
  if (user.phoneNumber && user.phoneVerifiedAt && isSmsAvailable()) {
    await sendSms({ to: user.phoneNumber, body: `Noirly recovery code: ${code}. Don't share it.`, kind: "recovery_code" }).catch(() => undefined);
  }
  return hashToken(`recovery-code:${code}`);
}

export function matchesRecoveryCode(code: string, hash: string | null | undefined) {
  return Boolean(hash) && hashToken(`recovery-code:${code.trim()}`) === hash;
}
