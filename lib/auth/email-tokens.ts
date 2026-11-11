import { isBlockedUser } from "@/lib/auth/user-policy";
import { AppError } from "@/lib/api/errors";
import { getEnv } from "@/lib/config/env";
import { sendEmail } from "@/lib/email/email-service";
import {
  buildAddressVerificationEmail,
  buildVerificationEmail,
  maskEmail,
  redactSecretInUrl,
} from "@/lib/email/templates";
import { generateSecureToken, hashToken } from "@/lib/security/crypto";
import { EmailVerificationToken } from "@/models/EmailVerificationToken";
import { PasswordResetToken } from "@/models/PasswordResetToken";
import { User } from "@/models/User";
import { UserEmail } from "@/models/UserEmail";
import { emailCodeHash, emailCodeMatches, isEmailCode, MAX_CODE_ATTEMPTS, newEmailCode, spacedCode } from "@/lib/security/email-code";
import { consumeRateLimit } from "@/lib/security/shared-rate-limit";
import { recordEvent } from "@/lib/audit/event-log";
import { Types, type HydratedDocument } from "mongoose";
import type { EmailVerificationTokenDocument } from "@/models/EmailVerificationToken";

export type EmailVerificationResult =
  | { status: "verified" }
  | { status: "already_verified" }
  | { status: "invalid" }
  | { status: "expired" }
  | { status: "used" }
  | { status: "taken" };

/** The primary address's outstanding links; an additional address's are its own (`addressId`). */
export async function invalidateUnusedVerificationTokens(
  userId: Types.ObjectId | string,
  addressId: Types.ObjectId | string | null = null,
): Promise<void> {
  await EmailVerificationToken.updateMany(
    { userId, addressId, usedAt: null },
    { usedAt: new Date() },
  );
}

export async function issueEmailVerification(
  userId: Types.ObjectId | string,
  email: string,
  name = "there",
): Promise<{ token: string }> {
  const env = getEnv();
  const token = generateSecureToken(32);
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + env.EMAIL_TOKEN_TTL_SECONDS * 1000);
  // A code too, for where opening the link is awkward (a phone app, another device).
  const code = newEmailCode();
  const id = new Types.ObjectId();

  await invalidateUnusedVerificationTokens(userId);

  await EmailVerificationToken.create({
    _id: id,
    userId,
    tokenHash,
    codeHash: emailCodeHash(String(id), code),
    expiresAt,
  });

  const verifyUrl = `${env.APP_URL}/verify-email?token=${encodeURIComponent(token)}`;
  const expiresInHours = Math.max(
    1,
    Math.round(env.EMAIL_TOKEN_TTL_SECONDS / 3600),
  );
  const template = buildVerificationEmail({
    name,
    verifyUrl,
    expiresInHours,
    code: spacedCode(code),
  });

  await sendEmail({
    to: email,
    subject: template.subject,
    text: template.text,
    html: template.html,
    // Development helper metadata only; provider must redact secrets.
    meta: {
      kind: "email_verification",
      previewUrl: redactSecretInUrl(verifyUrl),
    },
  });

  return { token };
}

export async function verifyEmailToken(
  rawToken: string,
): Promise<EmailVerificationResult> {
  if (!rawToken || rawToken.length < 20) {
    return { status: "invalid" };
  }

  const record = await EmailVerificationToken.findOne({
    tokenHash: hashToken(rawToken),
  });

  if (!record) {
    return { status: "invalid" };
  }

  return applyVerification(record);
}

/**
 * Confirms an account's primary address with the six-digit code from its
 * verification email. A wrong code counts against that email's code, which
 * stops working after MAX_CODE_ATTEMPTS; every failure reads "invalid".
 */
export async function verifyEmailCode(rawEmail: string, rawCode: string): Promise<EmailVerificationResult> {
  const email = rawEmail.trim().toLowerCase();
  const code = rawCode.replace(/\s+/g, "");
  if (!isEmailCode(code)) return { status: "invalid" };
  const limited = await consumeRateLimit(`verify-code:${email}`, 20, 3600);
  if (!limited.allowed) throw new AppError("Too many tries. Ask for a new email.", 429, "rate_limited");
  const user = await User.findOne({ email }).select("_id emailVerified").lean();
  if (!user) return { status: "invalid" };
  if (user.emailVerified) return { status: "already_verified" };
  const record = await EmailVerificationToken.findOne({ userId: user._id, addressId: null, usedAt: null, expiresAt: { $gt: new Date() } }).sort({ createdAt: -1 });
  if (!record) return { status: "invalid" };
  if (!emailCodeMatches(String(record._id), code, record.codeHash)) {
    record.attempts = (record.attempts ?? 0) + 1;
    if (record.attempts >= MAX_CODE_ATTEMPTS) record.usedAt = new Date();
    await record.save();
    return { status: "invalid" };
  }
  return applyVerification(record);
}

async function applyVerification(record: HydratedDocument<EmailVerificationTokenDocument>): Promise<EmailVerificationResult> {
  if (record.usedAt) {
    if (record.addressId) {
      const address = await UserEmail.exists({ _id: record.addressId, verifiedAt: { $ne: null } });
      return { status: address ? "already_verified" : "used" };
    }
    const user = await User.findById(record.userId);
    if (user?.emailVerified) {
      return { status: "already_verified" };
    }
    return { status: "used" };
  }

  if (record.expiresAt.getTime() <= Date.now()) {
    return { status: "expired" };
  }

  if (record.addressId) return verifyAdditionalAddress(record);

  const user = await User.findById(record.userId);
  if (!user || isBlockedUser(user)) {
    return { status: "invalid" };
  }

  if (user.emailVerified) {
    record.usedAt = new Date();
    await record.save();
    return { status: "already_verified" };
  }

  record.usedAt = new Date();
  await record.save();

  user.emailVerified = true;
  user.status = "active";
  await user.save();

  await invalidateUnusedVerificationTokens(user._id);
  await recordEvent({ action: "account.email_verified", subjectId: user._id, actorId: null, data: { email: user.email } });

  return { status: "verified" };
}

/** Whether an address already belongs to an account: as its primary, or as a verified additional one. */
export async function addressTaken(email: string, exceptUserId?: Types.ObjectId | string) {
  const notMine = exceptUserId ? { $ne: exceptUserId } : { $exists: true };
  const [primary, additional] = await Promise.all([
    User.exists({ email, _id: notMine }),
    UserEmail.exists({ email, verifiedAt: { $ne: null }, userId: notMine }),
  ]);
  return Boolean(primary || additional);
}

/**
 * Sends the link that proves an additional address is the account's. It
 * goes to the new address, and says who asked, so a stranger who gets it
 * knows to ignore it.
 */
export async function issueAddressVerification(
  userId: Types.ObjectId | string,
  addressId: Types.ObjectId | string,
  email: string,
  accountEmail: string,
): Promise<void> {
  const env = getEnv();
  const token = generateSecureToken(32);
  await invalidateUnusedVerificationTokens(userId, addressId);
  await EmailVerificationToken.create({
    userId,
    addressId,
    tokenHash: hashToken(token),
    expiresAt: new Date(Date.now() + env.EMAIL_TOKEN_TTL_SECONDS * 1000),
  });
  const verifyUrl = `${env.APP_URL}/verify-email?token=${encodeURIComponent(token)}`;
  const template = buildAddressVerificationEmail({
    accountEmail: maskEmail(accountEmail),
    verifyUrl,
    expiresInHours: Math.max(1, Math.round(env.EMAIL_TOKEN_TTL_SECONDS / 3600)),
  });
  await sendEmail({
    to: email,
    subject: template.subject,
    text: template.text,
    html: template.html,
    meta: { kind: "address_verification", previewUrl: redactSecretInUrl(verifyUrl) },
  });
}

async function verifyAdditionalAddress(record: { _id: Types.ObjectId; userId: Types.ObjectId; addressId?: Types.ObjectId | null; usedAt?: Date | null; save(): Promise<unknown> }): Promise<EmailVerificationResult> {
  const address = await UserEmail.findOne({ _id: record.addressId, userId: record.userId });
  const user = await User.findById(record.userId);
  if (!address || !user || isBlockedUser(user)) return { status: "invalid" };
  record.usedAt = new Date();
  await record.save();
  if (address.verifiedAt) return { status: "already_verified" };
  // Someone may have proved it theirs since this one was added.
  if (await addressTaken(address.email, user._id)) return { status: "taken" };
  address.verifiedAt = new Date();
  try {
    await address.save();
  } catch (error) {
    if ((error as { code?: number }).code === 11000) return { status: "taken" };
    throw error;
  }
  // Anyone else's unproved claim on it is now moot.
  await UserEmail.deleteMany({ email: address.email, verifiedAt: null, userId: { $ne: user._id } });
  await recordEvent({ action: "email.verified", subjectId: user._id, actorId: null, data: { email: address.email } });
  return { status: "verified" };
}

export async function issuePasswordReset(
  email: string,
): Promise<{ issued: boolean }> {
  const env = getEnv();
  const user = await User.findOne({ email: email.trim().toLowerCase() });

  if (!user || isBlockedUser(user)) {
    return { issued: true };
  }

  const token = generateSecureToken(32);
  const expiresAt = new Date(
    Date.now() + env.PASSWORD_RESET_TTL_SECONDS * 1000,
  );

  await PasswordResetToken.create({
    userId: user._id,
    tokenHash: hashToken(token),
    expiresAt,
  });

  const resetUrl = `${env.APP_URL}/reset-password?token=${encodeURIComponent(token)}`;
  await sendEmail({
    to: user.email,
    subject: "Reset your Noirly password",
    text: `Reset your password by opening this link: ${resetUrl}`,
    html: `<p>Reset your password by opening this link:</p><p><a href="${resetUrl}">Reset password</a></p>`,
    meta: {
      kind: "password_reset",
      previewUrl: redactSecretInUrl(resetUrl),
    },
  });

  return { issued: true };
}

export async function consumePasswordResetToken(
  token: string,
): Promise<{ userId: string } | null> {
  const record = await PasswordResetToken.findOne({
    tokenHash: hashToken(token),
  });
  if (!record || record.usedAt || record.expiresAt.getTime() <= Date.now()) {
    return null;
  }

  record.usedAt = new Date();
  await record.save();
  return { userId: String(record.userId) };
}

export function verificationResultToError(
  result: EmailVerificationResult,
): AppError | null {
  switch (result.status) {
    case "verified":
    case "already_verified":
      return null;
    case "expired":
      return new AppError(
        "This verification link has expired.",
        400,
        "token_expired",
      );
    case "used":
      return new AppError(
        "This verification link is invalid or has already been used.",
        400,
        "token_used",
      );
    case "invalid":
    default:
      return new AppError(
        "This verification link is invalid or has already been used.",
        400,
        "invalid_token",
      );
  }
}
