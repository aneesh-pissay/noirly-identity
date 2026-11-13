import { isBlockedUser } from "@/lib/auth/user-policy";
import { requireSecondFactor, type MobileMfaContext } from "@/lib/security/mfa";
import { consumeRateLimit } from "@/lib/security/shared-rate-limit";
import { AppError } from "@/lib/api/errors";
import {
  addressTaken,
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
import { Avatar } from "@/models/Avatar";
import { accessibilityOf } from "@/lib/account/preferences";
import { frontchannelLogoutUrls } from "@/lib/oidc/backchannel-logout";
import { recordEvent, type RequestMeta } from "@/lib/audit/event-log";
import type { PublicUser } from "@/types";
import type {
  changePasswordSchema,
  loginSchema,
  registerSchema,
  updateProfileSchema,
} from "@/lib/validation/schemas";
import type { z } from "zod";
import { assertNotBreached, breachCount } from "@/lib/security/breached-passwords";
import { checkSignupAllowed } from "@/lib/security/signup-protection";
import { assessSignInRisk } from "@/lib/security/risk";
import { afterResponse } from "@/lib/api/after";
import { sendEmail } from "@/lib/email/email-service";
import { buildNoticeEmail } from "@/lib/email/templates";

type RegisterInput = z.infer<typeof registerSchema>;
type LoginInput = z.infer<typeof loginSchema>;
type UpdateProfileInput = z.infer<typeof updateProfileSchema>;
type ChangePasswordInput = z.infer<typeof changePasswordSchema>;

export async function registerUser(
  input: RegisterInput,
  meta: { ipAddress?: string | null; userAgent?: string | null; place?: string | null; deviceId?: string | null; mobileMfa?: MobileMfaContext },
): Promise<{ user: PublicUser; sessionToken: string }> {
  const email = normalizeEmail(input.email);
  // Throwaway inboxes and many accounts from one place (lib/security/signup-protection.ts).
  await checkSignupAllowed(email, meta);
  // An address confirmed on another account is that account's, even if not its primary.
  if (await addressTaken(email)) {
    throw new AppError("Unable to create account", 409, "registration_failed");
  }

  await assertNotBreached(input.password);
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
    place: meta.place,
    methods: ["password"],
  });
  await recordEvent({ action: "account.registered", subjectId: user._id, clientId: meta.mobileMfa?.clientId, request: meta, data: { method: "password" } });

  return { user: toPublicUser(user), sessionToken: token };
}

export async function loginUser(
  input: LoginInput,
  meta: { ipAddress?: string | null; userAgent?: string | null; place?: string | null; deviceId?: string | null; mobileMfa?: MobileMfaContext },
): Promise<{ user: PublicUser; sessionToken: string }> {
  const env = getEnv();
  const email = normalizeEmail(input.email);
  // Credential stuffing tries many accounts from one device or address: limit those too, whichever account is tried.
  await enforceAcrossAccounts(meta);
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
    // Only for accounts that exist: a guess at an address nobody has isn't anyone's history.
    if (user) await recordEvent({ action: "auth.sign_in_failed", subjectId: user._id, actorId: null, clientId: meta.mobileMfa?.clientId, request: meta, data: { method: "password", reason: "wrong_password" } });
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

  // A risky sign-in asks for a second step even when it's optional (lib/security/risk.ts).
  const risk = await assessSignInRisk(user._id, meta);
  await requireSecondFactor(user._id.toString(), meta.mobileMfa, "password", risk);

  user.lastLoginAt = new Date();
  await user.save();
  // Is the password they just used known from breaches? Checked after the response; they're told by email.
  const usedPassword = input.password;
  afterResponse(() => flagIfBreached(String(user._id), usedPassword));

  const { token } = await createSession({
    userId: user._id,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
    place: meta.place,
    deviceId: meta.deviceId,
    methods: ["password"],
  });
  await recordEvent({ action: "auth.signed_in", subjectId: user._id, clientId: meta.mobileMfa?.clientId, request: meta, data: { methods: ["password"] } });

  return { user: toPublicUser(user), sessionToken: token };
}

/** Signs this browser out; returns the front-channel logout URLs for apps the back-channel didn't reach. */
export async function logoutCurrentSession(sessionToken: string | null, meta: RequestMeta = {}): Promise<{ frontchannelLogoutUrls: string[] }> {
  if (!sessionToken) {
    return { frontchannelLogoutUrls: [] };
  }
  const ctx = await validateSession(sessionToken);
  const ended = await revokeSessionByToken(sessionToken);
  if (ctx) await recordEvent({ action: "auth.signed_out", subjectId: ctx.userId, request: meta });
  return { frontchannelLogoutUrls: ended.session ? await frontchannelLogoutUrls(ended.session, ended.backchannelFailed) : [] };
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
  meta: RequestMeta = {},
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
  if (input.avatarUrl === null) {
    user.avatarUrl = null;
    // An uploaded photo stops being served too.
    await Avatar.deleteOne({ userId: user._id });
  }
  if (input.phoneNumber !== undefined && input.phoneNumber !== user.phoneNumber) {
    user.phoneNumber = input.phoneNumber;
    // A number typed in here hasn't been proved; verifying it again is lib/account/phone.ts.
    user.phoneVerifiedAt = null;
  }
  if (input.locale !== undefined) user.locale = input.locale;
  if (input.zoneinfo !== undefined) user.zoneinfo = input.zoneinfo;
  if (input.accessibility) {
    const next = { ...accessibilityOf(user.accessibility), ...input.accessibility };
    const current = accessibilityOf(user.accessibility);
    if (next.motion !== current.motion || next.contrast !== current.contrast || next.textSize !== current.textSize) user.set("accessibility", next);
  }

  // Which fields changed, not what they changed to: the log isn't a copy of the profile.
  const fields = user.modifiedPaths().filter((path) => ["firstName", "lastName", "displayName", "avatarUrl", "phoneNumber", "locale", "zoneinfo", "accessibility"].includes(path));
  await user.save();
  if (fields.length) {
    await recordEvent({ action: "account.profile_updated", subjectId: user._id, request: meta, data: { fields } });
    const { emitLifecycle } = await import("@/lib/webhooks/lifecycle");
    await emitLifecycle("user.updated", { userId: String(user._id), data: { fields } });
  }
  return toPublicUser(user);
}

export async function changeUserPassword(
  sessionToken: string | null,
  input: ChangePasswordInput,
  meta: RequestMeta = {},
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

  await assertNotBreached(input.newPassword);
  user.passwordHash = await hashPassword(input.newPassword);
  user.passwordBreachedAt = null;
  await user.save();
  await revokeAllUserSessions(user._id, ctx.session._id);
  await recordEvent({ action: "password.changed", subjectId: user._id, request: meta, data: { otherSessionsSignedOut: true } });
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
  meta: RequestMeta = {},
): Promise<void> {
  const consumed = await consumePasswordResetToken(token);
  if (!consumed) {
    throw new AppError("Invalid or expired reset token", 400, "invalid_token");
  }

  const user = await User.findById(consumed.userId).select("+passwordHash");
  if (!user || isBlockedUser(user)) {
    throw new AppError("Invalid or expired reset token", 400, "invalid_token");
  }

  await assertNotBreached(newPassword);
  user.passwordHash = await hashPassword(newPassword);
  user.passwordBreachedAt = null;
  user.mustResetPassword = false;
  await user.save();
  await revokeAllUserSessions(user._id);
  await recordEvent({ action: "password.reset", subjectId: user._id, actorId: null, request: meta, data: { allSessionsSignedOut: true } });
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

/** A sign-in used a password known from breaches: flag the account and tell its owner. */
export async function flagIfBreached(userId: string, password: string) {
  if ((await breachCount(password)) === 0) return;
  const user = await User.findOneAndUpdate({ _id: userId, passwordBreachedAt: null }, { $set: { passwordBreachedAt: new Date() } }).select("email").lean();
  if (!user) return;
  await recordEvent({ action: "password.breach_detected", subjectId: userId, actorId: null });
  await sendEmail({
    to: user.email,
    ...buildNoticeEmail({
      subject: "Change your Noirly password",
      paragraphs: [
        "The password you signed in with has appeared in a data breach somewhere else. Anyone with that list could try it on your Noirly account.",
        "Change it now, and turn on a passkey or an authenticator app if you haven't.",
      ],
      action: { label: "Change your password", url: new URL("/account/security#password", getEnv().APP_URL).toString() },
    }),
    meta: { kind: "password-breached" },
  });
}

/** Password attempts across accounts: per device (20 in 15 minutes) and per address (60 in 15 minutes, for shared networks). */
export const DEVICE_ATTEMPTS = 20;
export const ADDRESS_ATTEMPTS = 60;
async function enforceAcrossAccounts(meta: { ipAddress?: string | null; deviceId?: string | null }) {
  const checks = [
    meta.deviceId ? consumeRateLimit(`login-device:${meta.deviceId}`, DEVICE_ATTEMPTS, 900) : null,
    meta.ipAddress ? consumeRateLimit(`login-address:${meta.ipAddress}`, ADDRESS_ATTEMPTS, 900) : null,
  ];
  for (const result of await Promise.all(checks)) {
    if (result && !result.allowed) {
      throw new AppError("Too many sign-in attempts from here. Try again later.", 429, "rate_limited", { retryAfterSeconds: result.retryAfterSeconds });
    }
  }
}
