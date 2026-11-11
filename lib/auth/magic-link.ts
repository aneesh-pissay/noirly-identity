import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { emailCodeHash, emailCodeMatches, isEmailCode, MAX_CODE_ATTEMPTS, newEmailCode, spacedCode } from "@/lib/security/email-code";
import { deviceLabel } from "@/lib/audit/activity";
import { recordEvent, type RequestMeta } from "@/lib/audit/event-log";
import { sanitizeReturnTo } from "@/lib/auth/return-to";
import { normalizeEmail, toPublicUser } from "@/lib/auth/user-mapper";
import { isBlockedUser } from "@/lib/auth/user-policy";
import { getEnv } from "@/lib/config/env";
import { sendEmail } from "@/lib/email/email-service";
import { buildMagicLinkEmail, redactSecretInUrl } from "@/lib/email/templates";
import { generateSecureToken, hashToken, safeEqualHex } from "@/lib/security/crypto";
import { requireSecondFactor } from "@/lib/security/mfa";
import { consumeRateLimit } from "@/lib/security/shared-rate-limit";
import { createSession } from "@/lib/sessions/session-service";
import { MagicLink } from "@/models/MagicLink";
import { User } from "@/models/User";

/**
 * Passwordless sign-in by email. Asking sets a secret in the asking
 * browser's cookie and emails a link; the link signs in only together with
 * that secret, once, within MAGIC_LINK_MINUTES. Someone else's address
 * typed in gets them nothing but an email to its owner, who can ignore it.
 * An authenticator or passkey, if the account has one, is still asked for.
 */

export const MAGIC_LINK_MINUTES = 15;
export const MAGIC_COOKIE = "noirly_magic";
/** Links one address can be sent in an hour, whoever asks. */
const LINKS_PER_HOUR = 5;

/**
 * Sends a link if the address is an account's primary one. Answers the same
 * either way (so it can't be used to find out who has an account), always
 * with the browser secret for the cookie.
 */
export async function requestMagicLink(rawEmail: string, returnTo: string | null, meta: RequestMeta = {}, existingSecret: string | null = null): Promise<{ browserSecret: string }> {
  // One secret per browser, so asking twice doesn't break the first link.
  const browserSecret = existingSecret && /^[A-Za-z0-9_-]{40,64}$/.test(existingSecret) ? existingSecret : generateSecureToken(32);
  const email = normalizeEmail(rawEmail);
  const user = await User.findOne({ email }).lean();
  // Unverified accounts sign in by confirming their address first.
  if (!user || isBlockedUser(user) || user.status !== "active" || !user.emailVerified) return { browserSecret };
  const limited = await consumeRateLimit(`magic-link:${email}`, LINKS_PER_HOUR, 3600);
  if (!limited.allowed) return { browserSecret };

  const token = generateSecureToken(32);
  const code = newEmailCode();
  const env = getEnv();
  const safeReturn = sanitizeReturnTo(returnTo, env.APP_URL) ?? "/account";
  const id = new Types.ObjectId();
  await MagicLink.create({
    _id: id,
    userId: user._id,
    tokenHash: hashToken(token),
    browserHash: hashToken(browserSecret),
    codeHash: emailCodeHash(String(id), code),
    returnTo: safeReturn,
    expiresAt: new Date(Date.now() + MAGIC_LINK_MINUTES * 60_000),
  });
  const url = new URL("/magic-link", env.APP_URL);
  url.searchParams.set("token", token);
  // In the link too, for the page to carry through a second-factor step.
  if (safeReturn !== "/account") url.searchParams.set("return_to", safeReturn);
  const signInUrl = url.toString();
  const message = buildMagicLinkEmail({ signInUrl, code: spacedCode(code), expiresInMinutes: MAGIC_LINK_MINUTES, device: deviceLabel(meta.userAgent) });
  await sendEmail({ to: user.email, subject: message.subject, text: message.text, html: message.html, meta: { kind: "magic_link", previewUrl: redactSecretInUrl(signInUrl) } });
  await recordEvent({ action: "auth.magic_link_sent", subjectId: user._id, actorId: null, request: meta });
  return { browserSecret };
}

/**
 * Signs in with a link and the browser secret. A link opened in another
 * browser is refused without being used up, so the right browser can still
 * use it.
 */
export async function verifyMagicLink(token: string, browserSecret: string | null, meta: RequestMeta = {}) {
  const record = token.length >= 20 ? await MagicLink.findOne({ tokenHash: hashToken(token) }).lean() : null;
  if (!record) throw new AppError("This sign-in link is invalid", 400, "invalid_token");
  if (record.usedAt) throw new AppError("This sign-in link was already used. Ask for a new one.", 400, "token_used");
  if (record.expiresAt.getTime() <= Date.now()) throw new AppError(`This sign-in link has expired: links work for ${MAGIC_LINK_MINUTES} minutes. Ask for a new one.`, 400, "token_expired");
  if (!browserSecret || !safeEqualHex(hashToken(browserSecret), record.browserHash)) {
    throw new AppError("Open this link in the browser where you asked for it.", 400, "other_browser");
  }
  return finishSignIn(record, "magic_link", meta);
}

const WRONG_CODE = "That code isn't right, or it has expired. Check the latest email, or ask for a new one.";

/**
 * Signs in with the six-digit code from the same email, typed into the
 * browser that asked (it needs that browser's secret, like the link).
 * Every failure reads the same, so the code can't be used to probe accounts.
 */
export async function verifyMagicCode(rawEmail: string, rawCode: string, browserSecret: string | null, meta: RequestMeta = {}) {
  const email = normalizeEmail(rawEmail);
  const code = rawCode.replace(/\s+/g, "");
  if (!isEmailCode(code) || !browserSecret) throw new AppError(WRONG_CODE, 400, "invalid_code");
  const limited = await consumeRateLimit(`magic-code:${email}`, 20, 3600);
  if (!limited.allowed) throw new AppError("Too many tries. Ask for a new link.", 429, "rate_limited");
  const user = await User.findOne({ email }).select("_id").lean();
  if (!user) throw new AppError(WRONG_CODE, 400, "invalid_code");
  // The newest live code this browser asked for.
  const record = await MagicLink.findOne({ userId: user._id, browserHash: hashToken(browserSecret), usedAt: null, expiresAt: { $gt: new Date() } }).sort({ createdAt: -1 }).lean();
  if (!record) throw new AppError(WRONG_CODE, 400, "invalid_code");
  if (!emailCodeMatches(String(record._id), code, record.codeHash)) {
    const attempts = (record.attempts ?? 0) + 1;
    // Out of tries: the code, and its link, are done.
    await MagicLink.updateOne({ _id: record._id }, { $set: { attempts, ...(attempts >= MAX_CODE_ATTEMPTS ? { usedAt: new Date() } : {}) } });
    throw new AppError(WRONG_CODE, 400, "invalid_code");
  }
  return finishSignIn(record, "email_code", meta);
}

async function finishSignIn(record: { _id: Types.ObjectId; userId: Types.ObjectId; returnTo?: string | null }, method: "magic_link" | "email_code", meta: RequestMeta) {
  const claimed = await MagicLink.updateOne({ _id: record._id, usedAt: null }, { $set: { usedAt: new Date() } });
  if (claimed.modifiedCount !== 1) throw new AppError("This sign-in link was already used. Ask for a new one.", 400, "token_used");

  const user = await User.findById(record.userId).select("+passwordHash");
  if (!user || isBlockedUser(user) || user.status !== "active" || !user.emailVerified) throw new AppError("This account can't sign in", 401, "unauthorized");
  await requireSecondFactor(user._id.toString(), undefined, method);

  user.lastLoginAt = new Date();
  await user.save();
  const { token: sessionToken } = await createSession({ userId: user._id, ipAddress: meta.ipAddress, userAgent: meta.userAgent, place: meta.place, methods: [method] });
  await recordEvent({ action: "auth.signed_in", subjectId: user._id, request: meta, data: { methods: [method] } });
  return { sessionToken, user: toPublicUser(user), returnTo: record.returnTo ?? "/account" };
}
