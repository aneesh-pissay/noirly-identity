import { Schema, Types, model, models, type Model } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { ADMIN_STREAM } from "@/lib/audit/chain";
import { recordEvent, type RequestMeta } from "@/lib/audit/event-log";
import { normalizeEmail } from "@/lib/auth/user-mapper";
import { getEnv } from "@/lib/config/env";
import { sendEmail } from "@/lib/email/email-service";
import { buildNoticeEmail } from "@/lib/email/templates";
import { generateSecureToken, hashToken } from "@/lib/security/crypto";
import { consumeRateLimit } from "@/lib/security/shared-rate-limit";
import { revokeAllUserSessions } from "@/lib/sessions/session-service";
import { AccessToken } from "@/models/AccessToken";
import { RefreshToken } from "@/models/RefreshToken";
import { User } from "@/models/User";
import { UserEmail } from "@/models/UserEmail";

/**
 * Locking an account.
 * - "Freeze my account": the owner stops all sign-ins at once (from the
 *   account page, or from the link in any security alert, without signing
 *   in): every device is signed out and every app token revoked.
 * - Unfreezing: asked for by email; each verified address (and the recovery
 *   address) gets a link, and opening it unfreezes the account after
 *   UNFREEZE_WAIT_HOURS, with a link to stop that on every channel. Whoever
 *   froze it has a day to notice a thief unfreezing.
 * - Admins lock with a reason (and contain a takeover, lib/security/containment.ts);
 *   only an admin unlocks those.
 */

export const UNFREEZE_WAIT_HOURS = 24;
const LINK_DAYS = 7;

type LockTokenPurpose = "freeze" | "unfreeze" | "cancel-unfreeze" | "undo-closure";
const lockTokenSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
  purpose: { type: String, enum: ["freeze", "unfreeze", "cancel-unfreeze", "undo-closure"], required: true },
  tokenHash: { type: String, required: true, unique: true },
  expiresAt: { type: Date, required: true, index: { expireAfterSeconds: 0 } },
});
export const AccountLockToken: Model<{ userId: Types.ObjectId; purpose: LockTokenPurpose; tokenHash: string; expiresAt: Date }> =
  (models.AccountLockToken as never) || model("AccountLockToken", lockTokenSchema, "account_lock_tokens");

async function linkFor(userIdInput: unknown, purpose: LockTokenPurpose, path: string) {
  const userId = new Types.ObjectId(String(userIdInput));
  const token = generateSecureToken(32);
  await AccountLockToken.create({ userId, purpose, tokenHash: hashToken(token), expiresAt: new Date(Date.now() + LINK_DAYS * 86_400_000) });
  const url = new URL(path, getEnv().APP_URL);
  url.searchParams.set("token", token);
  return url.toString();
}

/** A one-click "freeze my account" link for an email (security alerts carry one). */
export async function freezeLink(userId: unknown) {
  return linkFor(userId, "freeze", "/freeze");
}

async function addressesOf(userIdInput: unknown) {
  const userId = new Types.ObjectId(String(userIdInput));
  const user = await User.findById(userId).select("email recoveryEmail recoveryEmailVerifiedAt").lean();
  if (!user) return [];
  const extras = (await UserEmail.find({ userId, verifiedAt: { $ne: null } }).select("email").lean()).map((e) => e.email);
  return [...new Set([user.email, ...extras, ...(user.recoveryEmail && user.recoveryEmailVerifiedAt ? [user.recoveryEmail] : [])])];
}

async function lockNow(userId: Types.ObjectId, set: Record<string, unknown>) {
  const now = new Date();
  await User.updateOne({ _id: userId }, { $set: { lockedAt: now, unlockAt: null, ...set } });
  await Promise.all([
    AccessToken.updateMany({ userId, revokedAt: null }, { $set: { revokedAt: now } }),
    RefreshToken.updateMany({ userId, revokedAt: null }, { $set: { revokedAt: now } }),
  ]);
  return revokeAllUserSessions(userId);
}

/** The owner freezes their own account (signed in, or by a freeze link). */
export async function freezeAccount(userId: string, meta: RequestMeta = {}) {
  const user = await User.findById(userId).select("lockedAt lockKind").lean();
  if (!user) throw new AppError("No such account", 404, "not_found");
  // An admin or an organization (deprovisioned) lock stays theirs to lift: freezing must not turn it into one the owner can undo.
  if (user.lockedAt && (user.lockKind === "admin" || user.lockKind === "deprovisioned")) return { alreadyLocked: true };
  const ended = await lockNow(user._id, { lockKind: "self", lockReason: "Frozen by its owner", lockedBy: user._id });
  await recordEvent({ action: "account.frozen", subjectId: userId, request: meta, data: { sessionsEnded: ended } });
  for (const to of await addressesOf(user._id)) {
    await sendEmail({
      to,
      ...buildNoticeEmail({
        subject: "Your Noirly account is frozen",
        paragraphs: ["Your account is frozen: nobody can sign in, every device was signed out and apps lost access.", "When you're ready, ask to unfreeze it from the sign-in page. It unfreezes a day after you confirm by email."],
      }),
      meta: { kind: "account-frozen" },
    }).catch(() => undefined);
  }
  return { alreadyLocked: false };
}

export async function freezeByLink(token: string, meta: RequestMeta = {}) {
  const record = token.length >= 20 ? await AccountLockToken.findOneAndDelete({ tokenHash: hashToken(token), purpose: "freeze", expiresAt: { $gt: new Date() } }).lean() : null;
  if (!record) throw new AppError("This link has expired. Sign in and freeze your account from the account page.", 400, "invalid_token");
  return freezeAccount(String(record.userId), meta);
}

/** Asks to unfreeze: every address gets a confirmation link. Same answer whether or not the account exists or is frozen. */
export async function requestUnfreeze(emailInput: string) {
  const email = normalizeEmail(emailInput);
  const limit = await consumeRateLimit(`unfreeze:${email}`, 3, 3600);
  if (!limit.allowed) return;
  const user = await User.findOne({ email }).select("lockedAt lockKind").lean();
  if (!user || !user.lockedAt || user.lockKind !== "self") return;
  for (const to of await addressesOf(user._id)) {
    const link = await linkFor(user._id, "unfreeze", "/unfreeze");
    await sendEmail({
      to,
      ...buildNoticeEmail({
        subject: "Unfreeze your Noirly account?",
        paragraphs: [`Someone asked to unfreeze your account. If it's you, confirm here; it unfreezes ${UNFREEZE_WAIT_HOURS} hours later. If it isn't you, ignore this.`],
        action: { label: "Unfreeze my account", url: link },
      }),
      meta: { kind: "unfreeze-request" },
    }).catch(() => undefined);
  }
}

/** Confirms an unfreeze: it happens after the wait, and every channel can stop it. */
export async function confirmUnfreeze(token: string, meta: RequestMeta = {}) {
  const record = token.length >= 20 ? await AccountLockToken.findOneAndDelete({ tokenHash: hashToken(token), purpose: "unfreeze", expiresAt: { $gt: new Date() } }).lean() : null;
  if (!record) throw new AppError("This link has expired. Ask again from the sign-in page.", 400, "invalid_token");
  const unlockAt = new Date(Date.now() + UNFREEZE_WAIT_HOURS * 3_600_000);
  const result = await User.updateOne({ _id: record.userId, lockKind: "self", lockedAt: { $ne: null } }, { $set: { unlockAt } });
  if (!result.matchedCount) throw new AppError("This account isn't frozen", 409, "not_frozen");
  await recordEvent({ action: "account.unfreeze_scheduled", subjectId: String(record.userId), actorId: null, request: meta, data: { unlockAt: unlockAt.toISOString() } });
  for (const to of await addressesOf(record.userId)) {
    const cancel = await linkFor(record.userId, "cancel-unfreeze", "/unfreeze");
    await sendEmail({
      to,
      ...buildNoticeEmail({
        subject: "Your Noirly account unfreezes tomorrow",
        paragraphs: [`Your account unfreezes at ${unlockAt.toUTCString()}. If you didn't ask for this, stop it now: it stays frozen.`],
        action: { label: "Keep it frozen", url: cancel },
      }),
      meta: { kind: "unfreeze-scheduled" },
    }).catch(() => undefined);
  }
  return { unlockAt: unlockAt.toISOString() };
}

export async function cancelUnfreeze(token: string, meta: RequestMeta = {}) {
  const record = token.length >= 20 ? await AccountLockToken.findOneAndDelete({ tokenHash: hashToken(token), purpose: "cancel-unfreeze", expiresAt: { $gt: new Date() } }).lean() : null;
  if (!record) throw new AppError("This link has expired.", 400, "invalid_token");
  await User.updateOne({ _id: record.userId, lockKind: "self" }, { $set: { unlockAt: null } });
  await recordEvent({ action: "account.unfreeze_cancelled", subjectId: String(record.userId), actorId: null, request: meta });
}

/** Admin: locks an account with a reason (signs it out, revokes its tokens), or unlocks one. */
export async function adminLock(adminId: string, userId: string, reason: string, meta: RequestMeta = {}) {
  const why = reason.trim();
  if (why.length < 5 || why.length > 300) throw new AppError("Say why (5 to 300 characters)", 400, "invalid_request");
  if (!Types.ObjectId.isValid(userId)) throw new AppError("No such account", 404, "not_found");
  const id = new Types.ObjectId(userId);
  if (!(await User.exists({ _id: id }))) throw new AppError("No such account", 404, "not_found");
  const ended = await lockNow(id, { lockKind: "admin", lockReason: why, lockedBy: new Types.ObjectId(adminId) });
  await recordEvent({ action: "account.locked", stream: ADMIN_STREAM, actorId: adminId, subjectId: userId, request: meta, data: { reason: why, sessionsEnded: ended } });
  await recordEvent({ action: "account.locked", subjectId: userId, actorId: adminId, request: meta, data: { sessionsEnded: ended } });
}

/** Is the account locked right now? (A confirmed unfreeze whose wait is over isn't.) */
export function isLockedNow(user: { lockedAt?: Date | null; unlockAt?: Date | null }, now = Date.now()) {
  if (!user.lockedAt) return false;
  return !(user.unlockAt && user.unlockAt.getTime() <= now);
}
