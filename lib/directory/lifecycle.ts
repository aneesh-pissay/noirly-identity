import { Schema, Types, model, models, type Model } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { orgStream } from "@/lib/audit/chain";
import { recordEvent } from "@/lib/audit/event-log";
import { revokeAllUserSessions } from "@/lib/sessions/session-service";
import { canAdminister, roleIn } from "@/lib/spaces/space-service";
import { emitLifecycle } from "@/lib/webhooks/lifecycle";
import { AccessToken } from "@/models/AccessToken";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { RefreshToken } from "@/models/RefreshToken";
import { SecurityChallenge } from "@/models/SecurityCredential";
import { SpaceDomain } from "@/models/SpaceDomain";
import { SpaceTeam } from "@/models/SpaceTeam";
import { User } from "@/models/User";

/**
 * Offboarding and reactivation.
 *
 * Deactivating a member takes them out of the space at once (membership,
 * teams, and every token issued for the space), but keeps what they had, so
 * reactivating puts it all back. When the person's address is at one of the
 * space's verified domains, the space owns that identity: their whole account
 * is locked too, every session and token ends, and apps are told (back-channel
 * logout and the `user.deactivated` lifecycle webhook). Reactivating unlocks
 * it. An address elsewhere is the person's own: only the membership goes.
 */

type Kept = {
  organizationId: Types.ObjectId;
  userId: Types.ObjectId;
  role: string;
  adminAreas?: string[] | null;
  attributes?: Map<string, string> | Record<string, string> | null;
  scimExternalId?: string | null;
  teamIds: Types.ObjectId[];
  deactivatedAt: Date;
  deactivatedBy: Types.ObjectId | null;
  via: string;
  accountLocked: boolean;
};

const keptSchema = new Schema<Kept>({
  organizationId: { type: Schema.Types.ObjectId, required: true, index: true },
  userId: { type: Schema.Types.ObjectId, required: true },
  role: { type: String, required: true },
  adminAreas: { type: [String], default: undefined },
  attributes: { type: Map, of: String, default: undefined },
  scimExternalId: { type: String, default: null },
  teamIds: { type: [Schema.Types.ObjectId], default: [] },
  deactivatedAt: { type: Date, required: true },
  deactivatedBy: { type: Schema.Types.ObjectId, default: null },
  via: { type: String, required: true },
  accountLocked: { type: Boolean, default: false },
});
keptSchema.index({ organizationId: 1, userId: 1 }, { unique: true });
export const DeactivatedMembership: Model<Kept> = (models.DeactivatedMembership as never) || model("DeactivatedMembership", keptSchema, "deactivated_memberships");

export type Via = "admin" | "scim" | "bulk";
export type Actor = { actorId: string | null; via: Via };

/** Admins with the members area (SCIM is checked by its token instead). */
export async function requireMembersAdmin(spaceId: string, actorId: string) {
  if (!(await roleIn(spaceId, actorId))) throw new AppError("Space not found", 404, "not_found");
  if (!(await canAdminister(spaceId, actorId, "members"))) throw new AppError("You don't have permission to do that", 403, "forbidden");
}

/** Is this address at one of the space's verified domains (an identity the space owns)? */
export async function isManagedAddress(spaceId: Types.ObjectId, email: string) {
  const domain = email.split("@")[1]?.toLowerCase();
  return Boolean(domain && (await SpaceDomain.exists({ organizationId: spaceId, domain, verifiedAt: { $ne: null } })));
}

export async function deactivateMember(spaceIdInput: string, userIdInput: string, actor: Actor, reason = "Deactivated") {
  const space = new Types.ObjectId(spaceIdInput);
  const userId = new Types.ObjectId(userIdInput);
  const membership = await OrganizationMembership.findOne({ organizationId: space, userId }).lean();
  if (!membership) throw new AppError("Not a member of this space", 404, "not_found");
  if (membership.role === "owner") throw new AppError("Owners can't be deactivated; hand over ownership first", 400, "owner");
  if (actor.actorId && actor.actorId === userIdInput) throw new AppError("You can't deactivate yourself", 400, "invalid_request");
  const user = await User.findById(userId);
  if (!user) throw new AppError("Not a member of this space", 404, "not_found");

  const teams = await SpaceTeam.find({ organizationId: space, memberIds: userId }).select("_id").lean();
  const managed = await isManagedAddress(space, user.email);
  const now = new Date();
  await DeactivatedMembership.updateOne(
    { organizationId: space, userId },
    {
      $set: {
        role: membership.role,
        adminAreas: membership.adminAreas ?? null,
        attributes: membership.attributes ?? null,
        scimExternalId: (membership as { scimExternalId?: string | null }).scimExternalId ?? null,
        teamIds: teams.map((t) => t._id),
        deactivatedAt: now,
        deactivatedBy: actor.actorId ? new Types.ObjectId(actor.actorId) : null,
        via: actor.via,
        accountLocked: managed && !user.lockedAt,
      },
    },
    { upsert: true },
  );
  await SpaceTeam.updateMany({ organizationId: space, memberIds: userId }, { $pull: { memberIds: userId } });
  await OrganizationMembership.deleteOne({ _id: membership._id });

  let sessionsEnded = 0;
  if (managed) {
    // The space owns this identity: the whole account stops, everywhere.
    if (!user.lockedAt) {
      user.lockedAt = now;
      user.lockKind = "deprovisioned";
      user.lockReason = reason.slice(0, 300);
      user.lockedByOrganization = space;
      user.unlockAt = null;
      await user.save();
    }
    await Promise.all([
      AccessToken.updateMany({ userId, revokedAt: null }, { $set: { revokedAt: now } }),
      RefreshToken.updateMany({ userId, revokedAt: null }, { $set: { revokedAt: now } }),
      SecurityChallenge.deleteMany({ userId }),
    ]);
    sessionsEnded = await revokeAllUserSessions(userId);
  } else {
    // Only what was issued for this space.
    await Promise.all([
      AccessToken.updateMany({ userId, organizationId: space, revokedAt: null }, { $set: { revokedAt: now } }),
      RefreshToken.updateMany({ userId, organizationId: space, revokedAt: null }, { $set: { revokedAt: now } }),
    ]);
  }

  const data = { organizationId: spaceIdInput, via: actor.via, accountLocked: managed, sessionsEnded, reason };
  await recordEvent({ action: "directory.member_deactivated", stream: orgStream(spaceIdInput), actorId: actor.actorId, subjectId: userIdInput, data });
  if (managed) await recordEvent({ action: "account.locked", subjectId: userIdInput, actorId: actor.actorId, data: { by: "organization", organizationId: spaceIdInput, reason } });
  await emitLifecycle("membership.changed", { userId: userIdInput, organizationId: spaceIdInput, data: { change: "deactivated" } });
  if (managed) await emitLifecycle("user.deactivated", { userId: userIdInput, organizationId: spaceIdInput });
  return { accountLocked: managed, sessionsEnded };
}

export async function reactivateMember(spaceIdInput: string, userIdInput: string, actor: Actor) {
  const space = new Types.ObjectId(spaceIdInput);
  const userId = new Types.ObjectId(userIdInput);
  const kept = await DeactivatedMembership.findOne({ organizationId: space, userId }).lean();
  if (!kept) throw new AppError("No deactivated membership for that person", 404, "not_found");
  const user = await User.findById(userId);
  if (!user) throw new AppError("That account no longer exists", 404, "not_found");
  await OrganizationMembership.updateOne(
    { organizationId: space, userId },
    {
      $setOnInsert: {
        role: kept.role,
        ...(kept.adminAreas ? { adminAreas: kept.adminAreas } : {}),
        ...(kept.attributes ? { attributes: kept.attributes } : {}),
        scimExternalId: kept.scimExternalId ?? null,
      },
    },
    { upsert: true },
  );
  if (kept.teamIds.length) await SpaceTeam.updateMany({ _id: { $in: kept.teamIds }, organizationId: space }, { $addToSet: { memberIds: userId } });
  await DeactivatedMembership.deleteOne({ _id: (kept as { _id?: Types.ObjectId })._id });

  // Unlock only a lock this space put on.
  const unlocked = user.lockKind === "deprovisioned" && String(user.lockedByOrganization) === spaceIdInput;
  if (unlocked) {
    user.lockedAt = null;
    user.lockKind = null;
    user.lockReason = null;
    user.lockedByOrganization = null;
    await user.save();
  }
  await recordEvent({ action: "directory.member_reactivated", stream: orgStream(spaceIdInput), actorId: actor.actorId, subjectId: userIdInput, data: { organizationId: spaceIdInput, via: actor.via, accountUnlocked: unlocked } });
  if (unlocked) await recordEvent({ action: "account.unlocked", subjectId: userIdInput, actorId: actor.actorId, data: { by: "organization", organizationId: spaceIdInput } });
  await emitLifecycle("membership.changed", { userId: userIdInput, organizationId: spaceIdInput, data: { change: "reactivated", role: kept.role } });
  if (unlocked) await emitLifecycle("user.reactivated", { userId: userIdInput, organizationId: spaceIdInput });
  return { accountUnlocked: unlocked };
}

/** Removes a deactivated person from the space for good (SCIM DELETE); a locked managed account stays locked. */
export async function forgetDeactivated(spaceIdInput: string, userIdInput: string) {
  await DeactivatedMembership.deleteOne({ organizationId: new Types.ObjectId(spaceIdInput), userId: new Types.ObjectId(userIdInput) });
}

export async function listDeactivated(actorId: string, spaceId: string) {
  await requireMembersAdmin(spaceId, actorId);
  const kept = await DeactivatedMembership.find({ organizationId: new Types.ObjectId(spaceId) }).sort({ deactivatedAt: -1 }).lean();
  const users = new Map((await User.find({ _id: { $in: kept.map((k) => k.userId) } }).select("email displayName").lean()).map((u) => [String(u._id), u]));
  return kept.map((k) => ({
    userId: String(k.userId),
    email: users.get(String(k.userId))?.email ?? null,
    name: users.get(String(k.userId))?.displayName ?? null,
    role: k.role,
    deactivatedAt: k.deactivatedAt.toISOString(),
    via: k.via,
    accountLocked: k.accountLocked,
  }));
}
