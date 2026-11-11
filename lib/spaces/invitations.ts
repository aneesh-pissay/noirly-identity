import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { normalizeEmail } from "@/lib/auth/user-mapper";
import { getEnv } from "@/lib/config/env";
import { sendEmail } from "@/lib/email/email-service";
import { buildNoticeEmail } from "@/lib/email/templates";
import { generateSecureToken, hashToken } from "@/lib/security/crypto";
import { Organization } from "@/models/Organization";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { SpaceInvitation } from "@/models/SpaceInvitation";
import { User } from "@/models/User";
import { UserEmail } from "@/models/UserEmail";
import { canAdminister, getSpace, roleIn, type SpaceRole } from "@/lib/spaces/space-service";

/**
 * Invitations: how people join a space. An admin invites an email address with
 * a role; the invitee gets a link that works for a week, and joins by opening
 * it signed in to an account that owns that address (verified). People without
 * an account sign up first and come back to the link. The link is the secret,
 * and only its hash is kept.
 */

export const INVITATION_DAYS = 7;

export type InvitationView = { id: string; email: string; role: SpaceRole; invitedAt: string; expiresAt: string };

const RANK: Record<SpaceRole, number> = { member: 1, admin: 2, owner: 3 };

function view(i: { _id: Types.ObjectId; email: string; role: string; createdAt: Date; expiresAt: Date }): InvitationView {
  return { id: String(i._id), email: i.email, role: i.role as SpaceRole, invitedAt: i.createdAt.toISOString(), expiresAt: i.expiresAt.toISOString() };
}

async function requireAdmin(spaceId: string, actorId: string) {
  const role = await roleIn(spaceId, actorId);
  if (!role) throw new AppError("Space not found", 404, "not_found");
  if (RANK[role] < RANK.admin || !(await canAdminister(spaceId, actorId, "members"))) throw new AppError("You don't have permission to do that", 403, "forbidden");
  return role;
}

/** Invites someone (admins; only owners invite owners). A newer invitation to the same address replaces the older. */
export async function inviteToSpace(actorId: string, spaceId: string, emailInput: string, role: SpaceRole) {
  const actorRole = await requireAdmin(spaceId, actorId);
  if (role === "owner" && actorRole !== "owner") throw new AppError("Only an owner can invite owners", 403, "forbidden");
  const email = normalizeEmail(emailInput);
  const space = new Types.ObjectId(spaceId);
  const existing = await User.findOne({ email }).select("_id").lean();
  if (existing && (await OrganizationMembership.exists({ organizationId: space, userId: existing._id }))) {
    throw new AppError("They're already in this space", 409, "already_member");
  }
  const now = new Date();
  await SpaceInvitation.updateMany({ organizationId: space, email, acceptedAt: null, revokedAt: null }, { $set: { revokedAt: now } });
  const token = generateSecureToken(32);
  const invitation = await SpaceInvitation.create({
    organizationId: space,
    email,
    role,
    tokenHash: hashToken(token),
    invitedBy: new Types.ObjectId(actorId),
    expiresAt: new Date(now.getTime() + INVITATION_DAYS * 86_400_000),
  });
  const [org, inviter] = await Promise.all([
    Organization.findById(space).select("name").lean(),
    User.findById(actorId).select("displayName").lean(),
  ]);
  const url = new URL("/invitations/accept", getEnv().APP_URL);
  url.searchParams.set("token", token);
  await sendEmail({
    to: email,
    ...buildNoticeEmail({
      subject: `Join ${org?.name ?? "a space"} on Noirly`,
      paragraphs: [
        `${inviter?.displayName ?? "Someone"} invited you to join ${org?.name ?? "their space"} on Noirly as ${role === "member" ? "a member" : `an ${role}`}.`,
        "Open the link signed in to your Noirly account for this address. No account yet? Create one with this address first, then open the link again.",
      ],
      action: { label: "Join the space", url: url.toString() },
      footer: [`The invitation expires in ${INVITATION_DAYS} days. If you weren't expecting it, ignore this email.`],
    }),
    meta: { kind: "space-invitation" },
  });
  return { invitation: view(invitation), token };
}

/** Pending invitations (admins). */
export async function listInvitations(actorId: string, spaceId: string): Promise<InvitationView[]> {
  await requireAdmin(spaceId, actorId);
  const pending = await SpaceInvitation.find({ organizationId: new Types.ObjectId(spaceId), acceptedAt: null, revokedAt: null, expiresAt: { $gt: new Date() } }).sort({ createdAt: -1 }).lean();
  return pending.map(view);
}

export async function revokeInvitation(actorId: string, spaceId: string, invitationId: string) {
  await requireAdmin(spaceId, actorId);
  if (!Types.ObjectId.isValid(invitationId)) throw new AppError("Invitation not found", 404, "not_found");
  const result = await SpaceInvitation.updateOne(
    { _id: new Types.ObjectId(invitationId), organizationId: new Types.ObjectId(spaceId), acceptedAt: null, revokedAt: null },
    { $set: { revokedAt: new Date() } },
  );
  if (!result.modifiedCount) throw new AppError("Invitation not found", 404, "not_found");
}

/** What the accept page shows before joining: the space and the role, or why the link doesn't work. */
export async function previewInvitation(token: string) {
  const invitation = await SpaceInvitation.findOne({ tokenHash: hashToken(token) }).lean();
  if (!invitation || invitation.revokedAt || invitation.acceptedAt || invitation.expiresAt <= new Date()) {
    throw new AppError("This invitation has expired or was withdrawn. Ask for a new one.", 410, "invitation_gone");
  }
  const space = await Organization.findOne({ _id: invitation.organizationId, status: "active" }).select("name").lean();
  if (!space) throw new AppError("This invitation has expired or was withdrawn. Ask for a new one.", 410, "invitation_gone");
  return { space: space.name, role: invitation.role as SpaceRole, email: invitation.email };
}

/**
 * Joins with the invitation, signed in as `userId`. The account must own the
 * invited address (primary, or another verified address), so a forwarded link
 * can't put someone else in the space.
 */
export async function acceptInvitation(userId: string, token: string) {
  const invitation = await SpaceInvitation.findOne({ tokenHash: hashToken(token) });
  if (!invitation || invitation.revokedAt || invitation.acceptedAt || invitation.expiresAt <= new Date()) {
    throw new AppError("This invitation has expired or was withdrawn. Ask for a new one.", 410, "invitation_gone");
  }
  const user = await User.findById(userId).select("email emailVerified status").lean();
  if (!user || !user.emailVerified || user.status !== "active") throw new AppError("Sign in to a verified account first", 403, "forbidden");
  const owns =
    user.email === invitation.email ||
    Boolean(await UserEmail.exists({ userId: user._id, email: invitation.email, verifiedAt: { $ne: null } }));
  if (!owns) {
    throw new AppError(`This invitation is for ${invitation.email}. Sign in to the account with that address, or add and confirm it on this one.`, 403, "wrong_account");
  }
  const space = invitation.organizationId;
  if (!(await Organization.exists({ _id: space, status: "active" }))) {
    throw new AppError("This invitation has expired or was withdrawn. Ask for a new one.", 410, "invitation_gone");
  }
  // Claimed once, even if opened twice at the same moment.
  const claimed = await SpaceInvitation.findOneAndUpdate(
    { _id: invitation._id, acceptedAt: null, revokedAt: null },
    { $set: { acceptedAt: new Date(), acceptedBy: user._id } },
  );
  if (!claimed) throw new AppError("This invitation has already been used", 410, "invitation_gone");
  if (!(await OrganizationMembership.exists({ organizationId: space, userId: user._id }))) {
    await OrganizationMembership.create({ organizationId: space, userId: user._id, role: invitation.role });
    if (invitation.teamIds?.length) {
      const { SpaceTeam } = await import("@/models/SpaceTeam");
      await SpaceTeam.updateMany({ _id: { $in: invitation.teamIds }, organizationId: space }, { $addToSet: { memberIds: user._id } });
    }
    const { membershipChanged } = await import("@/lib/spaces/space-service");
    await membershipChanged(String(user._id), String(space), "joined", invitation.role);
  }
  return { spaceId: String(space), space: await getSpace(String(space)) };
}
