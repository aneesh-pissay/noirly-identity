import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { recordEvent, listEvents, type RequestMeta } from "@/lib/audit/event-log";
import { getEnv } from "@/lib/config/env";
import { sendEmail } from "@/lib/email/email-service";
import { buildNoticeEmail } from "@/lib/email/templates";
import { generateSecureToken, hashToken } from "@/lib/security/crypto";
import { revokeAllUserSessions } from "@/lib/sessions/session-service";
import { deleteUserAccount } from "@/lib/account/delete-account";
import { listAppAccess } from "@/lib/account/app-access";
import { AccessToken } from "@/models/AccessToken";
import { LinkedAccount } from "@/models/LinkedAccount";
import { Organization } from "@/models/Organization";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { RefreshToken } from "@/models/RefreshToken";
import { Session } from "@/models/Session";
import { User } from "@/models/User";
import { UserEmail } from "@/models/UserEmail";
import { AccountLockToken } from "@/lib/security/account-lock";

/**
 * Closing an account, with a grace period. Closing signs it out everywhere
 * (apps told by back-channel logout), revokes every app token and locks it;
 * every address gets a link to undo it. After CLOSURE_GRACE_DAYS it's deleted
 * for good (lib/account/delete-account.ts, which tells apps to delete their
 * data too). Before closing, the person is offered everything Identity holds
 * about them (`exportIdentityData`).
 */

export const CLOSURE_GRACE_DAYS = 14;

async function addresses(userId: Types.ObjectId) {
  const user = await User.findById(userId).select("email recoveryEmail recoveryEmailVerifiedAt").lean();
  if (!user) return [];
  const extras = (await UserEmail.find({ userId, verifiedAt: { $ne: null } }).select("email").lean()).map((e) => e.email);
  return [...new Set([user.email, ...extras, ...(user.recoveryEmail && user.recoveryEmailVerifiedAt ? [user.recoveryEmail] : [])])];
}

export async function closeAccount(userIdInput: string, meta: RequestMeta = {}) {
  const userId = new Types.ObjectId(userIdInput);
  const now = new Date();
  const deleteAfter = new Date(now.getTime() + CLOSURE_GRACE_DAYS * 86_400_000);
  await User.updateOne({ _id: userId }, { $set: { lockedAt: now, lockKind: "closing", lockReason: "Closed by its owner", unlockAt: null, closingAt: now, deleteAfter } });
  await Promise.all([
    AccessToken.updateMany({ userId, revokedAt: null }, { $set: { revokedAt: now } }),
    RefreshToken.updateMany({ userId, revokedAt: null }, { $set: { revokedAt: now } }),
  ]);
  await revokeAllUserSessions(userId);
  await recordEvent({ action: "account.closing", subjectId: userIdInput, request: meta, data: { deleteAfter: deleteAfter.toISOString() } });
  for (const to of await addresses(userId)) {
    const token = generateSecureToken(32);
    await AccountLockToken.create({ userId, purpose: "undo-closure", tokenHash: hashToken(token), expiresAt: deleteAfter });
    const url = new URL("/close-account/undo", getEnv().APP_URL);
    url.searchParams.set("token", token);
    await sendEmail({
      to,
      ...buildNoticeEmail({
        subject: "Your Noirly account is closing",
        paragraphs: [
          `Your Noirly account is closed and will be deleted for good on ${deleteAfter.toUTCString()}, along with the data the Noirly apps hold for it.`,
          "Changed your mind, or wasn't it you? Undo it before then.",
        ],
        action: { label: "Keep my account", url: url.toString() },
      }),
      meta: { kind: "account-closing" },
    }).catch(() => undefined);
  }
  return { deleteAfter: deleteAfter.toISOString() };
}

/** Undoes a closure from the emailed link, within the grace period. The person then signs in again. */
export async function undoClosure(token: string, meta: RequestMeta = {}) {
  const record = token.length >= 20 ? await AccountLockToken.findOneAndDelete({ tokenHash: hashToken(token), purpose: "undo-closure", expiresAt: { $gt: new Date() } }).lean() : null;
  if (!record) throw new AppError("This link has expired, or the account was already reopened or deleted.", 400, "invalid_token");
  const result = await User.updateOne(
    { _id: record.userId, lockKind: "closing", deleteAfter: { $gt: new Date() } },
    { $set: { lockedAt: null, lockKind: null, lockReason: null, closingAt: null, deleteAfter: null } },
  );
  if (!result.modifiedCount) throw new AppError("This account isn't closing any more.", 409, "not_closing");
  await AccountLockToken.deleteMany({ userId: record.userId, purpose: "undo-closure" });
  await recordEvent({ action: "account.closure_undone", subjectId: String(record.userId), actorId: null, request: meta });
}

/** Deletes accounts whose grace period is over (run on a schedule). */
export async function sweepClosedAccounts(now = new Date()): Promise<number> {
  const due = await User.find({ lockKind: "closing", deleteAfter: { $lte: now } }).select("_id").lean();
  for (const user of due) await deleteUserAccount(user._id);
  return due.length;
}

/**
 * Everything Identity holds about an account, as one JSON document: profile,
 * addresses, sign-in methods (never secrets), sessions, apps, spaces and the
 * account's own activity log.
 */
export async function exportIdentityData(userIdInput: string) {
  const userId = new Types.ObjectId(userIdInput);
  const user = await User.findById(userId).lean();
  if (!user) throw new AppError("Authentication required", 401, "unauthorized");
  const [emails, links, sessions, memberships, apps, activity] = await Promise.all([
    UserEmail.find({ userId }).select("email verifiedAt createdAt").lean(),
    LinkedAccount.find({ userId }).select("provider email createdAt").lean(),
    Session.find({ userId, revokedAt: null, expiresAt: { $gt: new Date() } }).select("createdAt lastActivityAt userAgent place").lean(),
    OrganizationMembership.find({ userId }).select("organizationId role createdAt").lean(),
    listAppAccess(userIdInput),
    listEvents({ stream: `user:${userIdInput}` }).then((r) => r.events),
  ]);
  const orgs = new Map((await Organization.find({ _id: { $in: memberships.map((m) => m.organizationId) } }).select("name").lean()).map((o) => [String(o._id), o.name]));
  return {
    exportedAt: new Date().toISOString(),
    account: {
      id: String(user._id),
      email: user.email,
      emailVerified: user.emailVerified,
      firstName: user.firstName,
      lastName: user.lastName,
      displayName: user.displayName,
      phoneNumber: user.phoneNumber ?? null,
      locale: user.locale ?? null,
      zoneinfo: user.zoneinfo ?? null,
      roles: user.roles,
      createdAt: user.createdAt,
      lastLoginAt: user.lastLoginAt ?? null,
      recoveryEmail: user.recoveryEmail ?? null,
    },
    emails: emails.map((e) => ({ email: e.email, verified: Boolean(e.verifiedAt), addedAt: e.createdAt })),
    signInProviders: links.map((l) => ({ provider: l.provider, email: l.email ?? null, linkedAt: l.createdAt })),
    sessions: sessions.map((s) => ({ startedAt: s.createdAt, lastActiveAt: s.lastActivityAt, device: s.userAgent ?? null, place: s.place ?? null })),
    spaces: memberships.map((m) => ({ space: orgs.get(String(m.organizationId)) ?? null, role: m.role, joinedAt: m.createdAt })),
    apps,
    activity,
  };
}
