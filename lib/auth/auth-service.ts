import { isBlockedUser } from "@/lib/auth/user-policy";
import { requireSecondFactor, type MobileMfaContext } from "@/lib/security/mfa";
import { consumeRateLimit } from "@/lib/security/shared-rate-limit";
import { AppError } from "@/lib/api/errors";
import {
  issueEmailVerification,
  issuePasswordReset,
  consumePasswordResetToken,
  verifyEmailToken,
  type EmailVerificationResult,
} from "@/lib/auth/email-tokens";
import { normalizeEmail, toPublicUser } from "@/lib/auth/user-mapper";
import { getEnv } from "@/lib/config/env";
import { hashPassword, verifyPassword } from "@/lib/security/password";
import {
  checkCooldown,
  checkLoginAttempts,
  clearLoginAttempts,
  recordFailedLogin,
} from "@/lib/security/rate-limit";
import {
  createSession,
  revokeAllUserSessions,
  revokeSessionByToken,
  validateSession,
} from "@/lib/sessions/session-service";
import { User } from "@/models/User";
import type { PublicUser } from "@/types";
import type {
  changePasswordSchema,
  loginSchema,
  registerSchema,
  updateProfileSchema,
} from "@/lib/validation/schemas";
import type { z } from "zod";

type RegisterInput = z.infer<typeof registerSchema>;
type LoginInput = z.infer<typeof loginSchema>;
type UpdateProfileInput = z.infer<typeof updateProfileSchema>;
type ChangePasswordInput = z.infer<typeof changePasswordSchema>;

export async function registerUser(
  input: RegisterInput,
  meta: { ipAddress?: string | null; userAgent?: string | null; mobileMfa?: MobileMfaContext },
): Promise<{ user: PublicUser; sessionToken: string }> {
  const email = normalizeEmail(input.email);
  const existing = await User.findOne({ email });
  if (existing) {
    throw new AppError("Unable to create account", 409, "registration_failed");
  }

  const passwordHash = await hashPassword(input.password);
  const displayName =
    input.displayName?.trim() ||
    `${input.firstName.trim()} ${input.lastName.trim()}`.trim();

  const user = await User.create({
    email,
    passwordHash,
    firstName: input.firstName.trim(),
    lastName: input.lastName.trim(),
    displayName,
    phoneNumber: input.phoneNumber ?? null,
    status: "pending_verification",
    emailVerified: false,
    roles: ["user"],
  });

  await issueEmailVerification(user._id, user.email, user.firstName || displayName);

  const { token } = await createSession({
    userId: user._id,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
  });

  return { user: toPublicUser(user), sessionToken: token };
}

export async function loginUser(
  input: LoginInput,
  meta: { ipAddress?: string | null; userAgent?: string | null; mobileMfa?: MobileMfaContext },
): Promise<{ user: PublicUser; sessionToken: string }> {
  const env = getEnv();
  const email = normalizeEmail(input.email);
  if (env.NODE_ENV === "production" && email === "dev@noirly.test") throw new AppError("Invalid email or password", 401, "invalid_credentials");
  const attemptKey = `${meta.ipAddress ?? "unknown"}:${email}`;
  const accountLimit = await consumeRateLimit(`login-account:${email}`, env.LOGIN_MAX_ATTEMPTS, env.LOGIN_WINDOW_SECONDS);
  if (!accountLimit.allowed) throw new AppError("Too many login attempts. Try again later.", 429, "rate_limited", { retryAfterSeconds: accountLimit.retryAfterSeconds });

  const attempt = checkLoginAttempts(
    attemptKey,
    env.LOGIN_MAX_ATTEMPTS,
    env.LOGIN_WINDOW_SECONDS,
    env.LOGIN_LOCKOUT_SECONDS,
  );

  if (!attempt.allowed) {
    throw new AppError("Too many login attempts. Try again later.", 429, "rate_limited", {
      retryAfterSeconds: attempt.retryAfterSeconds,
    });
  }

  const user = await User.findOne({ email }).select("+passwordHash");
  const valid =
    !!user &&
    !!user.passwordHash &&
    (await verifyPassword(user.passwordHash, input.password));

  if (!user || !valid) {
    const failed = recordFailedLogin(
      attemptKey,
      env.LOGIN_MAX_ATTEMPTS,
      env.LOGIN_WINDOW_SECONDS,
      env.LOGIN_LOCKOUT_SECONDS,
    );
    if (!failed.allowed) {
      throw new AppError("Too many login attempts. Try again later.", 429, "rate_limited", {
        retryAfterSeconds: failed.retryAfterSeconds,
      });
    }
    throw new AppError("Invalid email or password", 401, "invalid_credentials");
  }

  if (isBlockedUser(user)) {
    throw new AppError("Invalid email or password", 401, "invalid_credentials");
  }

  if (!user.emailVerified || user.status === "pending_verification") {
    throw new AppError(
      "Please verify your email address before signing in.",
      403,
      "email_not_verified",
    );
  }

  clearLoginAttempts(attemptKey);

  await requireSecondFactor(user._id.toString(), meta.mobileMfa);

  user.lastLoginAt = new Date();
  await user.save();

  const { token } = await createSession({
    userId: user._id,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
  });

  return { user: toPublicUser(user), sessionToken: token };
}

export async function logoutCurrentSession(sessionToken: string | null): Promise<void> {
  if (!sessionToken) {
    return;
  }
  await revokeSessionByToken(sessionToken);
}

export async function getCurrentUser(
  sessionToken: string | null,
): Promise<PublicUser | null> {
  const ctx = await validateSession(sessionToken);
  if (!ctx) {
    return null;
  }
  const user = await User.findById(ctx.userId).select("+passwordHash").lean();
  if (!user || isBlockedUser(user)) {
    return null;
  }
  return toPublicUser(user);
}

export async function requireAdminUser(
  sessionToken: string | null,
): Promise<PublicUser> {
  const user = await getCurrentUser(sessionToken);
  if (!user) {
    throw new AppError("Authentication required", 401, "unauthorized");
  }
  if (!user.roles.includes("admin")) {
    throw new AppError("Admin access required", 403, "forbidden");
  }
  return user;
}

export async function updateUserProfile(
  sessionToken: string | null,
  input: UpdateProfileInput,
): Promise<PublicUser> {
  const ctx = await validateSession(sessionToken);
  if (!ctx) {
    throw new AppError("Authentication required", 401, "unauthorized");
  }

  const user = await User.findById(ctx.userId).select("+passwordHash");
  if (!user || isBlockedUser(user)) {
    throw new AppError("Authentication required", 401, "unauthorized");
  }

  if (input.firstName !== undefined) user.firstName = input.firstName;
  if (input.lastName !== undefined) user.lastName = input.lastName;
  if (input.displayName !== undefined) user.displayName = input.displayName;
  if (input.avatarUrl !== undefined) user.avatarUrl = input.avatarUrl;
  if (input.phoneNumber !== undefined) user.phoneNumber = input.phoneNumber;

  await user.save();
  return toPublicUser(user);
}

export async function changeUserPassword(
  sessionToken: string | null,
  input: ChangePasswordInput,
): Promise<void> {
  const ctx = await validateSession(sessionToken);
  if (!ctx) {
    throw new AppError("Authentication required", 401, "unauthorized");
  }

  const user = await User.findById(ctx.userId).select("+passwordHash");
  if (!user || isBlockedUser(user)) {
    throw new AppError("Authentication required", 401, "unauthorized");
  }

  const ok =
    !!user.passwordHash &&
    (await verifyPassword(user.passwordHash, input.currentPassword));
  if (!ok) {
    throw new AppError("Current password is incorrect", 400, "invalid_password");
  }

  user.passwordHash = await hashPassword(input.newPassword);
  await user.save();
  await revokeAllUserSessions(user._id, ctx.session._id);
}

export async function requestPasswordReset(email: string): Promise<void> {
  await issuePasswordReset(email);
}

export async function resendEmailVerification(email: string): Promise<{
  cooldownSeconds: number;
}> {
  const env = getEnv();
  const normalized = normalizeEmail(email);
  const cooldown = checkCooldown(
    `resend-verification:${normalized}`,
    env.RESEND_VERIFICATION_COOLDOWN_SECONDS,
  );

  if (!cooldown.allowed) {
    throw new AppError(
      "Please wait before requesting another verification email.",
      429,
      "resend_cooldown",
      { retryAfterSeconds: cooldown.retryAfterSeconds },
    );
  }

  const user = await User.findOne({ email: normalized });

  // Always succeed-shaped (aside from cooldown) to reduce account enumeration.
  if (!user || isBlockedUser(user) || user.emailVerified) {
    return { cooldownSeconds: env.RESEND_VERIFICATION_COOLDOWN_SECONDS };
  }

  await issueEmailVerification(
    user._id,
    user.email,
    user.firstName || user.displayName || "there",
  );

  return { cooldownSeconds: env.RESEND_VERIFICATION_COOLDOWN_SECONDS };
}

export async function resetUserPassword(
  token: string,
  newPassword: string,
): Promise<void> {
  const consumed = await consumePasswordResetToken(token);
  if (!consumed) {
    throw new AppError("Invalid or expired reset token", 400, "invalid_token");
  }

  const user = await User.findById(consumed.userId).select("+passwordHash");
  if (!user || isBlockedUser(user)) {
    throw new AppError("Invalid or expired reset token", 400, "invalid_token");
  }

  user.passwordHash = await hashPassword(newPassword);
  await user.save();
  await revokeAllUserSessions(user._id);
}

export async function confirmEmailVerification(
  token: string,
): Promise<EmailVerificationResult> {
  return verifyEmailToken(token);
}

export async function requireAuthContext(sessionToken: string | null) {
  const ctx = await validateSession(sessionToken);
  if (!ctx) {
    throw new AppError("Authentication required", 401, "unauthorized");
  }
  const user = await User.findById(ctx.userId);
  if (!user || isBlockedUser(user)) {
    throw new AppError("Authentication required", 401, "unauthorized");
  }
  return { ...ctx, user };
}
