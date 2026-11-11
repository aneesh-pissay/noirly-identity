import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { recordEvent, type RequestMeta } from "@/lib/audit/event-log";
import { addressTaken, invalidateUnusedVerificationTokens, issueAddressVerification, issuePasswordReset } from "@/lib/auth/email-tokens";
import { normalizeEmail } from "@/lib/auth/user-mapper";
import { getEnv } from "@/lib/config/env";
import { sendEmail } from "@/lib/email/email-service";
import { buildPrimaryChangedEmail, maskEmail, redactSecretInUrl } from "@/lib/email/templates";
import { generateSecureToken, hashToken } from "@/lib/security/crypto";
import { consumeRateLimit } from "@/lib/security/shared-rate-limit";
import { revokeAllUserSessions } from "@/lib/sessions/session-service";
import { spaceIdsForUser } from "@/lib/spaces/space-service";
import { notifySpaceChanged } from "@/lib/spaces/space-webhooks";
import { AccessToken } from "@/models/AccessToken";
import { EmailChangeUndo } from "@/models/EmailChangeUndo";
import { EmailVerificationToken } from "@/models/EmailVerificationToken";
import { RefreshToken } from "@/models/RefreshToken";
import { SecurityChallenge } from "@/models/SecurityCredential";
import { User } from "@/models/User";
import { UserEmail } from "@/models/UserEmail";

/**
 * An account's email addresses: the primary one (User.email, where sign-in
 * links and security notices go, and what apps see) and up to
 * MAX_ADDITIONAL more, each proved by a link sent to it. A proved address
 * can become the primary one; the old primary stays on as an additional one.
 */

export const MAX_ADDITIONAL = 5;
/** How long the old primary address can undo a change. */
export const UNDO_DAYS = 7;
/** Sending a confirmation link again: at most this many per address an hour. */
const RESENDS_PER_HOUR = 3;

export type EmailAddressView = { id: string; email: string; verified: boolean; addedAt: string };
export type EmailAddresses = { primary: string; additional: EmailAddressView[]; max: number };

function oid(id: string, what = "address") {
  if (!Types.ObjectId.isValid(id)) throw new AppError(`Invalid ${what}`, 400, "invalid_request");
  return new Types.ObjectId(id);
}

async function requireUser(userId: string) {
  const user = await User.findById(oid(userId, "account"));
  if (!user) throw new AppError("Authentication required", 401, "unauthorized");
  return user;
}

export async function listEmailAddresses(userId: string): Promise<EmailAddresses> {
  const user = await requireUser(userId);
  const rows = await UserEmail.find({ userId: user._id }).sort({ createdAt: 1 }).lean();
  return {
    primary: user.email,
    additional: rows.map((r) => ({ id: String(r._id), email: r.email, verified: Boolean(r.verifiedAt), addedAt: r.createdAt.toISOString() })),
    max: MAX_ADDITIONAL,
  };
}

/** Adds an address and sends it a confirmation link. It does nothing for the account until it's confirmed. */
export async function addEmailAddress(userId: string, rawEmail: string, meta: RequestMeta = {}) {
  const user = await requireUser(userId);
  const email = normalizeEmail(rawEmail);
  if (email === user.email) throw new AppError("That's already your primary address", 400, "already_primary");
  if (await UserEmail.exists({ userId: user._id, email })) throw new AppError("That address is already on your account", 409, "already_added");
  if (await UserEmail.countDocuments({ userId: user._id }) >= MAX_ADDITIONAL) throw new AppError(`You can add up to ${MAX_ADDITIONAL} addresses`, 400, "address_limit");
  // The same answer whoever holds it, so this can't be used to look people up beyond what sign-up already shows.
  if (await addressTaken(email, user._id)) throw new AppError("This address can't be added", 409, "address_unavailable");
  const limited = await consumeRateLimit(`email-add:${userId}`, 10, 3600);
  if (!limited.allowed) throw new AppError("Too many addresses added. Try again later.", 429, "rate_limited");
  const address = await UserEmail.create({ userId: user._id, email });
  await issueAddressVerification(user._id, address._id, email, user.email);
  await recordEvent({ action: "email.added", subjectId: user._id, request: meta, data: { email } });
  return listEmailAddresses(userId);
}

export async function resendAddressVerification(userId: string, addressId: string) {
  const user = await requireUser(userId);
  const address = await UserEmail.findOne({ _id: oid(addressId), userId: user._id }).lean();
  if (!address) throw new AppError("Address not found", 404, "not_found");
  if (address.verifiedAt) throw new AppError("That address is already confirmed", 400, "already_verified");
  const limited = await consumeRateLimit(`email-resend:${addressId}`, RESENDS_PER_HOUR, 3600);
  if (!limited.allowed) throw new AppError("Please wait before sending another link.", 429, "resend_cooldown", { retryAfterSeconds: limited.retryAfterSeconds });
  await issueAddressVerification(user._id, address._id, address.email, user.email);
}

export async function removeEmailAddress(userId: string, addressId: string, meta: RequestMeta = {}) {
  const user = await requireUser(userId);
  const removed = await UserEmail.findOneAndDelete({ _id: oid(addressId), userId: user._id }).lean();
  if (!removed) throw new AppError("Address not found", 404, "not_found");
  await invalidateUnusedVerificationTokens(user._id, removed._id);
  await recordEvent({ action: "email.removed", subjectId: user._id, request: meta, data: { email: removed.email, wasVerified: Boolean(removed.verifiedAt) } });
  return listEmailAddresses(userId);
}

/**
 * Makes a confirmed additional address the primary one. The caller checks
 * the person signed in recently. The old primary address is told, and
 * stays on as a confirmed additional address.
 */
export async function makePrimaryEmail(userId: string, addressId: string, meta: RequestMeta = {}) {
  const user = await requireUser(userId);
  const address = await UserEmail.findOne({ _id: oid(addressId), userId: user._id }).lean();
  if (!address) throw new AppError("Address not found", 404, "not_found");
  if (!address.verifiedAt) throw new AppError("Confirm the address before making it primary", 400, "not_verified");
  const previous = user.email;

  // One account per address, held by the indexes at every step: free the
  // new address, take it as primary, then keep the old one as additional.
  await UserEmail.deleteOne({ _id: address._id });
  try {
    await User.updateOne({ _id: user._id, email: previous }, { $set: { email: address.email } });
  } catch (error) {
    await UserEmail.create({ _id: address._id, userId: user._id, email: address.email, verifiedAt: address.verifiedAt });
    throw error;
  }
  await UserEmail.create({ userId: user._id, email: previous, verifiedAt: new Date() });
  // Links sent to the old primary address were for it as primary.
  await EmailVerificationToken.updateMany({ userId: user._id, addressId: null, usedAt: null }, { usedAt: new Date() });

  await recordEvent({ action: "email.primary_changed", subjectId: user._id, request: meta, data: { from: previous, to: address.email } });
  // The old address can take it back: whoever changed it may not be its owner.
  const undoToken = generateSecureToken(32);
  await EmailChangeUndo.create({ userId: user._id, from: previous, to: address.email, tokenHash: hashToken(undoToken), expiresAt: new Date(Date.now() + UNDO_DAYS * 86_400_000) });
  const undoUrl = `${getEnv().APP_URL}/undo-email-change?token=${encodeURIComponent(undoToken)}`;
  const notice = buildPrimaryChangedEmail({ newEmail: address.email, undoUrl, undoDays: UNDO_DAYS });
  await sendEmail({ to: previous, subject: notice.subject, text: notice.text, html: notice.html, meta: { kind: "primary_email_changed", previewUrl: redactSecretInUrl(undoUrl) } });
  // Spaces list members by email; apps that mirror them catch up.
  await notifySpaceChanged(await spaceIdsForUser(user._id));
  return listEmailAddresses(userId);
}

/**
 * "This wasn't me", from the undo link sent to the old primary address.
 * Puts that address back as primary, removes the address that replaced it
 * (and any made primary since), signs out every session and app, and sends
 * a password reset to the restored address if the account has a password.
 */
export async function undoPrimaryChange(token: string, meta: RequestMeta = {}): Promise<{ email: string; passwordResetSent: boolean }> {
  const record = token.length >= 20 ? await EmailChangeUndo.findOne({ tokenHash: hashToken(token) }).lean() : null;
  if (!record) throw new AppError("This link is invalid", 400, "invalid_token");
  if (record.usedAt) throw new AppError("This change has already been undone", 400, "token_used");
  if (record.expiresAt.getTime() <= Date.now()) throw new AppError(`This link has expired: undo links work for ${UNDO_DAYS} days. Reset your password from the sign-in page instead.`, 400, "token_expired");
  const user = await User.findById(record.userId).select("+passwordHash");
  if (!user) throw new AppError("This account no longer exists", 410, "gone");
  if (user.email !== record.from && (await addressTaken(record.from, user._id))) {
    throw new AppError("That address now belongs to another account, so it can't be put back. Reset your password from the sign-in page.", 409, "address_unavailable");
  }
  // One click wins, even if two arrive together.
  const claimed = await EmailChangeUndo.updateOne({ _id: record._id, usedAt: null }, { $set: { usedAt: new Date() } });
  if (claimed.modifiedCount !== 1) throw new AppError("This change has already been undone", 400, "token_used");

  const removed = [...new Set([record.to, user.email])].filter((email) => email !== record.from);
  if (user.email !== record.from) {
    await UserEmail.deleteOne({ userId: user._id, email: record.from });
    await User.updateOne({ _id: user._id }, { $set: { email: record.from, emailVerified: true } });
  }
  await UserEmail.deleteMany({ userId: user._id, email: { $in: removed } });

  // Lock out whoever made the change, wherever they're signed in.
  const now = new Date();
  await revokeAllUserSessions(user._id);
  await AccessToken.updateMany({ userId: user._id, revokedAt: null }, { $set: { revokedAt: now } });
  await RefreshToken.updateMany({ userId: user._id, revokedAt: null }, { $set: { revokedAt: now } });
  await SecurityChallenge.deleteMany({ userId: user._id });
  await EmailVerificationToken.updateMany({ userId: user._id, usedAt: null }, { $set: { usedAt: now } });
  await EmailChangeUndo.updateMany({ userId: user._id, usedAt: null }, { $set: { usedAt: now } });

  const passwordResetSent = Boolean(user.passwordHash);
  if (passwordResetSent) await issuePasswordReset(record.from);
  await recordEvent({ action: "email.change_undone", subjectId: user._id, actorId: null, request: meta, data: { restored: record.from, removed, signedOutEverywhere: true } });
  await notifySpaceChanged(await spaceIdsForUser(user._id));
  return { email: maskEmail(record.from), passwordResetSent };
}
