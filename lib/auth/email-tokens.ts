import { isBlockedUser } from "@/lib/auth/user-policy";
import { AppError } from "@/lib/api/errors";
import { getEnv } from "@/lib/config/env";
import { sendEmail } from "@/lib/email/email-service";
import {
  buildVerificationEmail,
  redactSecretInUrl,
} from "@/lib/email/templates";
import { generateSecureToken, hashToken } from "@/lib/security/crypto";
import { EmailVerificationToken } from "@/models/EmailVerificationToken";
import { PasswordResetToken } from "@/models/PasswordResetToken";
import { User } from "@/models/User";
import type { Types } from "mongoose";

export type EmailVerificationResult =
  | { status: "verified" }
  | { status: "already_verified" }
  | { status: "invalid" }
  | { status: "expired" }
  | { status: "used" };

export async function invalidateUnusedVerificationTokens(
  userId: Types.ObjectId | string,
): Promise<void> {
  await EmailVerificationToken.updateMany(
    { userId, usedAt: null },
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

  await invalidateUnusedVerificationTokens(userId);

  await EmailVerificationToken.create({
    userId,
    tokenHash,
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

  if (record.usedAt) {
    const user = await User.findById(record.userId);
    if (user?.emailVerified) {
      return { status: "already_verified" };
    }
    return { status: "used" };
  }

  if (record.expiresAt.getTime() <= Date.now()) {
    return { status: "expired" };
  }

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
