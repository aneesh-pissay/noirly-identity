import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { avatarUrlFor } from "@/lib/account/avatar";
import { mergePlan, type MergeRequestView, type MergeSide } from "@/lib/account/merge-plan";
import { notifyAccountMerged } from "@/lib/account/merge-webhooks";
import { purgeUserEvents, recordEvent, type RequestMeta } from "@/lib/audit/event-log";
import { SYSTEM_STREAM } from "@/lib/audit/chain";
import { normalizeEmail } from "@/lib/auth/user-mapper";
import { getEnv } from "@/lib/config/env";
import { sendEmail } from "@/lib/email/email-service";
import { buildMergeConfirmEmail, maskEmail, redactSecretInUrl } from "@/lib/email/templates";
import { generateSecureToken, hashToken } from "@/lib/security/crypto";
import { consumeRateLimit } from "@/lib/security/shared-rate-limit";
import { notifySpaceChanged } from "@/lib/spaces/space-webhooks";
import { AccessToken } from "@/models/AccessToken";
import { AccountMerge } from "@/models/AccountMerge";
import { AppAccess } from "@/models/AppAccess";
import { AuthorizationCode } from "@/models/AuthorizationCode";
import { Avatar } from "@/models/Avatar";
import { EmailChangeUndo } from "@/models/EmailChangeUndo";
import { EmailVerificationToken } from "@/models/EmailVerificationToken";
import { LinkedAccount } from "@/models/LinkedAccount";
import { MagicLink } from "@/models/MagicLink";
import { PhoneVerification } from "@/models/PhoneVerification";
import { FactorRecovery } from "@/models/FactorRecovery";
import { MobileBrowserLogin } from "@/models/MobileBrowserLogin";
import { Organization } from "@/models/Organization";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { PasswordResetToken } from "@/models/PasswordResetToken";
import { RefreshToken } from "@/models/RefreshToken";
import { Mfa, Passkey, SecurityChallenge } from "@/models/SecurityCredential";
import { Session } from "@/models/Session";
import { User } from "@/models/User";
import { UserEmail } from "@/models/UserEmail";

/**
 * Merging another account into this one (lib/account/merge-plan.ts says
 * what moves). Three steps, so both sides prove they're the same person:
 * this account asks (after a recent sign-in), the other account's address
 * confirms from an emailed link, and this account reviews and completes
 * (after a recent sign-in again).
 */

/** How long the emailed link works, and then how long the confirmed request waits to be completed. */
const CONFIRM_HOURS = 24;
const COMPLETE_HOURS = 24;
const RANK = { member: 1, admin: 2, owner: 3 } as const;

function oid(id: string | Types.ObjectId, what = "account") {
  if (!Types.ObjectId.isValid(String(id))) throw new AppError(`Invalid ${what}`, 400, "invalid_request");
  return new Types.ObjectId(String(id));
}

/** One side of a merge, as the plan needs it. */
async function sideOf(userId: Types.ObjectId): Promise<MergeSide> {
  const user = await User.findById(userId).select("+passwordHash").lean();
  if (!user) throw new AppError("Account not found", 404, "not_found");
  const [mfa, passkeys, links, emails, memberships, apps] = await Promise.all([
    Mfa.exists({ userId, enabled: true }),
    Passkey.countDocuments({ userId }),
    LinkedAccount.find({ userId }).lean(),
    UserEmail.find({ userId, verifiedAt: { $ne: null } }).lean(),
    OrganizationMembership.find({ userId }).lean(),
    AppAccess.countDocuments({ userId }),
  ]);
  const spaces = await Organization.find({ _id: { $in: memberships.map((m) => m.organizationId) }, status: "active" }).select("name").lean();
  const names = new Map(spaces.map((s) => [String(s._id), s.name]));
  return {
    email: user.email,
    password: Boolean(user.passwordHash),
    totp: Boolean(mfa),
    passkeys,
    providers: links.map((l) => ({ provider: l.provider, email: l.email ?? null })),
    verifiedEmails: emails.map((e) => e.email),
    photo: Boolean(user.avatarUrl),
    admin: user.roles.includes("admin"),
    spaces: memberships.filter((m) => names.has(String(m.organizationId))).map((m) => ({ id: String(m.organizationId), name: names.get(String(m.organizationId))!, role: m.role as MergeSide["spaces"][number]["role"] })),
    apps,
  };
}

/**
 * Starts a merge: sends a link to the other account's address. Says the same
 * whether or not an account has that address, so it can't be used to find
 * out who has one.
 */
export async function requestMerge(keeperId: string, rawEmail: string, meta: RequestMeta = {}) {
  const keeper = await User.findById(oid(keeperId));
  if (!keeper) throw new AppError("Authentication required", 401, "unauthorized");
  const limited = await consumeRateLimit(`merge-request:${keeperId}`, 5, 3600);
  if (!limited.allowed) throw new AppError("Too many merge requests. Try again later.", 429, "rate_limited");
  const email = normalizeEmail(rawEmail);
  const owner = (await User.findOne({ email }).select("_id email").lean())
    ?? (await UserEmail.findOne({ email, verifiedAt: { $ne: null } }).lean().then((row) => (row ? User.findById(row.userId).select("_id email").lean() : null)));
  if (owner?._id.equals(keeper._id)) throw new AppError("That address is already this account's", 400, "same_account");
  // One request at a time.
  await AccountMerge.updateMany({ keeperId: keeper._id, status: { $in: ["awaiting_confirmation", "confirmed"] } }, { $set: { status: "cancelled" } });
  await recordEvent({ action: "account.merge_requested", subjectId: keeper._id, request: meta, data: { email } });
  const token = generateSecureToken(32);
  await AccountMerge.create({ keeperId: keeper._id, sourceId: owner?._id ?? null, sourceEmail: email, tokenHash: hashToken(token), status: "awaiting_confirmation", expiresAt: new Date(Date.now() + CONFIRM_HOURS * 3_600_000) });
  if (!owner) return;
  const confirmUrl = `${getEnv().APP_URL}/merge-accounts?token=${encodeURIComponent(token)}`;
  // To the other account's primary address, whichever of its addresses was typed.
  const message = buildMergeConfirmEmail({ keeperEmail: maskEmail(keeper.email), confirmUrl, expiresInHours: CONFIRM_HOURS });
  await sendEmail({ to: owner.email, subject: message.subject, text: message.text, html: message.html, meta: { kind: "account_merge_confirm", previewUrl: redactSecretInUrl(confirmUrl) } });
}

/** The other account's owner says yes, from the emailed link. Nothing moves yet. */
export async function confirmMerge(token: string, meta: RequestMeta = {}) {
  const request = token.length >= 20 ? await AccountMerge.findOne({ tokenHash: hashToken(token) }).lean() : null;
  if (!request || !request.sourceId || request.status === "cancelled") throw new AppError("This link is invalid or was replaced by a newer request", 400, "invalid_token");
  if (request.status !== "awaiting_confirmation") throw new AppError("This merge was already confirmed", 400, "token_used");
  if (request.expiresAt.getTime() <= Date.now()) throw new AppError("This link has expired. Ask for the merge again.", 400, "token_expired");
  const claimed = await AccountMerge.updateOne(
    { _id: request._id, status: "awaiting_confirmation" },
    { $set: { status: "confirmed", confirmedAt: new Date(), expiresAt: new Date(Date.now() + COMPLETE_HOURS * 3_600_000) } },
  );
  if (claimed.modifiedCount !== 1) throw new AppError("This merge was already confirmed", 400, "token_used");
  await recordEvent({ action: "account.merge_confirmed", subjectId: request.keeperId, actorId: request.sourceId, request: meta, data: { email: request.sourceEmail } });
  const keeper = await User.findById(request.keeperId).select("email").lean();
  return { keeperEmail: keeper ? maskEmail(keeper.email) : null, completeWithinHours: COMPLETE_HOURS };
}

/** This account's open merge request, with what would move once it's confirmed. */
export async function currentMerge(keeperId: string): Promise<MergeRequestView | null> {
  const id = oid(keeperId);
  const request = await AccountMerge.findOne({ keeperId: id, status: { $in: ["awaiting_confirmation", "confirmed"] }, expiresAt: { $gt: new Date() } }).sort({ createdAt: -1 }).lean();
  if (!request) return null;
  const confirmed = request.status === "confirmed";
  return {
    id: String(request._id),
    status: request.status as MergeRequestView["status"],
    otherEmail: request.sourceEmail,
    expiresAt: request.expiresAt.toISOString(),
    // The plan shows only once the other side has proved it's yours.
    plan: confirmed && request.sourceId && (await User.exists({ _id: request.sourceId })) ? mergePlan(await sideOf(id), await sideOf(request.sourceId)) : null,
  };
}

export async function cancelMerge(keeperId: string, requestId: string, meta: RequestMeta = {}) {
  const updated = await AccountMerge.updateOne({ _id: oid(requestId, "request"), keeperId: oid(keeperId), status: { $in: ["awaiting_confirmation", "confirmed"] } }, { $set: { status: "cancelled" } });
  if (updated.modifiedCount !== 1) throw new AppError("No open merge to cancel", 404, "not_found");
  await recordEvent({ action: "account.merge_cancelled", subjectId: keeperId, request: meta });
}

/** Moves everything across, closes the other account, and tells apps where its `sub` went. */
export async function completeMerge(keeperId: string, requestId: string, meta: RequestMeta = {}) {
  const kId = oid(keeperId);
  const request = await AccountMerge.findOne({ _id: oid(requestId, "request"), keeperId: kId }).lean();
  if (request?.status === "completed") throw new AppError("This merge is already done", 409, "already_completed");
  if (!request || !request.sourceId || request.status !== "confirmed") throw new AppError("This merge hasn't been confirmed from the other account yet", 409, "not_confirmed");
  if (request.expiresAt.getTime() <= Date.now()) throw new AppError("This merge request has expired. Ask for it again.", 400, "request_expired");
  // Claimed first, so a second click can't run it twice.
  const claimed = await AccountMerge.updateOne({ _id: request._id, status: "confirmed" }, { $set: { status: "completed", completedAt: new Date() } });
  if (claimed.modifiedCount !== 1) throw new AppError("This merge is already done", 409, "already_completed");

  const sId = request.sourceId!;
  const keeper = await User.findById(kId).select("+passwordHash");
  const source = await User.findById(sId).select("+passwordHash");
  if (!keeper || !source) throw new AppError("One of the accounts no longer exists", 410, "gone");
  const plan = mergePlan(await sideOf(kId), await sideOf(sId));

  // Ways to sign in.
  if (!keeper.passwordHash && source.passwordHash) keeper.passwordHash = source.passwordHash;
  if (await Mfa.exists({ userId: sId, enabled: true }) && !(await Mfa.exists({ userId: kId, enabled: true }))) {
    await Mfa.deleteMany({ userId: kId });
    await Mfa.updateOne({ userId: sId }, { $set: { userId: kId } });
  }
  await Mfa.deleteMany({ userId: sId });
  await Passkey.updateMany({ userId: sId }, { $set: { userId: kId } });
  for (const link of await LinkedAccount.find({ userId: sId }).lean()) {
    if (await LinkedAccount.exists({ userId: kId, provider: link.provider })) await LinkedAccount.deleteOne({ _id: link._id });
    else await LinkedAccount.updateOne({ _id: link._id }, { $set: { userId: kId } });
  }

  // Addresses: confirmed ones come across confirmed; unconfirmed claims don't.
  await UserEmail.deleteMany({ userId: sId, verifiedAt: null });
  const kept = new Set([keeper.email, ...(await UserEmail.find({ userId: kId, verifiedAt: { $ne: null } }).lean()).map((e) => e.email)]);
  for (const address of await UserEmail.find({ userId: sId }).lean()) {
    if (kept.has(address.email)) {
      await UserEmail.deleteOne({ _id: address._id });
      continue;
    }
    await UserEmail.deleteMany({ userId: kId, email: address.email });
    await UserEmail.updateOne({ _id: address._id }, { $set: { userId: kId } });
    kept.add(address.email);
  }

  // Spaces: memberships move; where both are in a space, the higher role stays.
  const spaceIds: string[] = [];
  for (const membership of await OrganizationMembership.find({ userId: sId }).lean()) {
    spaceIds.push(String(membership.organizationId));
    const mine = await OrganizationMembership.findOne({ organizationId: membership.organizationId, userId: kId }).lean();
    if (!mine) {
      await OrganizationMembership.updateOne({ _id: membership._id }, { $set: { userId: kId } });
      continue;
    }
    if (RANK[membership.role as keyof typeof RANK] > RANK[mine.role as keyof typeof RANK]) await OrganizationMembership.updateOne({ _id: mine._id }, { $set: { role: membership.role } });
    await OrganizationMembership.deleteOne({ _id: membership._id });
  }

  // App history: one row per app, the widest scopes and the full span of use.
  for (const row of await AppAccess.find({ userId: sId }).lean()) {
    await AppAccess.updateOne(
      { userId: kId, clientId: row.clientId },
      { $addToSet: { scopes: { $each: row.scopes } }, $min: { firstUsedAt: row.firstUsedAt }, $max: { lastUsedAt: row.lastUsedAt } },
      { upsert: true },
    );
  }
  await AppAccess.deleteMany({ userId: sId });

  // Photo: the kept account's, unless it has none.
  const sourceAvatar = await Avatar.findOne({ userId: sId }).lean();
  if (!keeper.avatarUrl && source.avatarUrl) {
    if (sourceAvatar) {
      await Avatar.deleteMany({ userId: kId });
      await Avatar.updateOne({ _id: sourceAvatar._id }, { $set: { userId: kId } });
      keeper.avatarUrl = avatarUrlFor(String(kId), sourceAvatar.hash);
    } else {
      keeper.avatarUrl = source.avatarUrl;
    }
  } else {
    await Avatar.deleteMany({ userId: sId });
  }

  // Close the other account: signed out everywhere, then gone.
  await Promise.all([
    Session.deleteMany({ userId: sId }),
    AccessToken.deleteMany({ userId: sId }),
    RefreshToken.deleteMany({ userId: sId }),
    AuthorizationCode.deleteMany({ userId: sId }),
    SecurityChallenge.deleteMany({ userId: sId }),
    EmailVerificationToken.deleteMany({ userId: sId }),
    PasswordResetToken.deleteMany({ userId: sId }),
    MobileBrowserLogin.deleteMany({ userId: sId }),
    EmailChangeUndo.deleteMany({ userId: sId }),
    MagicLink.deleteMany({ userId: sId }),
    PhoneVerification.deleteMany({ userId: sId }),
    FactorRecovery.deleteMany({ userId: sId }),
    AccountMerge.updateMany({ $or: [{ keeperId: sId }, { sourceId: sId }], status: { $in: ["awaiting_confirmation", "confirmed"] } }, { $set: { status: "cancelled" } }),
  ]);
  const sourceEmail = source.email;
  await User.deleteOne({ _id: sId });
  if (!kept.has(sourceEmail)) {
    await UserEmail.deleteMany({ userId: kId, email: sourceEmail });
    await UserEmail.create({ userId: kId, email: sourceEmail, verifiedAt: new Date() });
  }
  await keeper.save();

  // Its own history goes; this account's records that it came in.
  await purgeUserEvents(sId);
  await recordEvent({ action: "account.merged", subjectId: kId, request: meta, data: { email: sourceEmail, from: String(sId), moves: plan.moves.length } });
  await recordEvent({ action: "account.merged", stream: SYSTEM_STREAM, subjectId: kId, actorId: kId, data: { from: String(sId), to: String(kId) } });
  const notices = await notifyAccountMerged(String(sId), String(kId));
  await notifySpaceChanged([...new Set(spaceIds)]);
  return { plan, ...notices };
}
