import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { ADMIN_STREAM } from "@/lib/audit/chain";
import { recordEvent, type RequestMeta } from "@/lib/audit/event-log";
import { issuePasswordReset } from "@/lib/auth/email-tokens";
import { normalizeEmail } from "@/lib/auth/user-mapper";
import { sendEmail } from "@/lib/email/email-service";
import { buildNoticeEmail } from "@/lib/email/templates";
import { revokeAllUserSessions } from "@/lib/sessions/session-service";
import { AccessToken } from "@/models/AccessToken";
import { RefreshToken } from "@/models/RefreshToken";
import { SecurityChallenge } from "@/models/SecurityCredential";
import { User } from "@/models/User";

/**
 * Account takeover containment: one admin action that
 * - locks the account (no sign-in of any kind; isBlockedUser), with a reason;
 * - signs it out everywhere (apps told by back-channel logout);
 * - revokes every app token it has;
 * - forces a password reset (the old password stops working).
 * The owner is told by email. Unlocking sends them a reset link; until they
 * use it, the old password stays gone. Passkeys and sign-in providers keep
 * working after unlock (they weren't what leaked); remove them separately if
 * they were.
 */

async function findUser(target: { userId?: string; email?: string }) {
  const filter = target.userId && Types.ObjectId.isValid(target.userId) ? { _id: new Types.ObjectId(target.userId) } : target.email ? { email: normalizeEmail(target.email) } : null;
  const user = filter ? await User.findOne(filter).select("+passwordHash") : null;
  if (!user) throw new AppError("No such account", 404, "not_found");
  return user;
}

export async function containAccount(adminId: string, target: { userId?: string; email?: string }, reason: string, meta: RequestMeta = {}) {
  const why = reason.trim();
  if (why.length < 5 || why.length > 300) throw new AppError("Say why (5 to 300 characters)", 400, "invalid_request");
  const user = await findUser(target);
  if (String(user._id) === adminId) throw new AppError("You can't lock your own account this way", 400, "invalid_request");
  const now = new Date();
  user.lockedAt = now;
  user.lockReason = why;
  user.lockedBy = new Types.ObjectId(adminId);
  user.lockKind = "admin";
  user.unlockAt = null;
  user.passwordHash = null;
  user.mustResetPassword = true;
  await user.save();
  // Tokens first (so they're counted), then the sessions, which also tells apps (back-channel logout).
  const [access, refresh] = await Promise.all([
    AccessToken.updateMany({ userId: user._id, revokedAt: null }, { $set: { revokedAt: now } }),
    RefreshToken.updateMany({ userId: user._id, revokedAt: null }, { $set: { revokedAt: now } }),
    SecurityChallenge.deleteMany({ userId: user._id }),
  ]);
  const ended = await revokeAllUserSessions(user._id);
  const data = { sessionsEnded: ended, tokensRevoked: access.modifiedCount + refresh.modifiedCount, reason: why };
  await recordEvent({ action: "account.contained", stream: ADMIN_STREAM, actorId: adminId, subjectId: String(user._id), request: meta, data });
  await recordEvent({ action: "account.contained", subjectId: String(user._id), actorId: adminId, request: meta, data: { sessionsEnded: ended } });
  await sendEmail({
    to: user.email,
    ...buildNoticeEmail({
      subject: "Your Noirly account is locked",
      paragraphs: [
        "We've locked your Noirly account to protect it: it may have been used by someone else. Every device has been signed out, apps have lost access, and your password no longer works.",
        "When it's unlocked you'll get an email to choose a new password. If you didn't expect this, reply to this email.",
      ],
    }),
    meta: { kind: "account-contained" },
  });
  return data;
}

/** Unlocks; the owner gets a link to choose a new password (the old one stays gone). */
export async function unlockAccount(adminId: string, target: { userId?: string; email?: string }, meta: RequestMeta = {}) {
  const user = await findUser(target);
  if (!user.lockedAt) throw new AppError("That account isn't locked", 409, "not_locked");
  // Admins can unlock anything, a frozen account included.
  user.lockedAt = null;
  user.lockReason = null;
  user.lockedBy = null;
  user.lockKind = null;
  user.unlockAt = null;
  await user.save();
  if (user.mustResetPassword) await issuePasswordReset(user.email);
  await recordEvent({ action: "account.unlocked", stream: ADMIN_STREAM, actorId: adminId, subjectId: String(user._id), request: meta });
  await recordEvent({ action: "account.unlocked", subjectId: String(user._id), actorId: adminId, request: meta });
}
