import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { normalizeEmail } from "@/lib/auth/user-mapper";
import { Organization } from "@/models/Organization";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { User } from "@/models/User";
import type { OrganizationRole } from "@/types";

/**
 * Spaces: one team shared by every Noirly app (stored as Organizations).
 *
 * A space's member list is the source of truth. Apps link their own team
 * (a Flow workspace, a Split group, ...) to a space and mirror its members;
 * people are added, removed and given roles here, never in the apps.
 */

export type SpaceRole = OrganizationRole;

export type SpaceSummary = {
  id: string;
  name: string;
  slug: string;
  role: SpaceRole;
  memberCount: number;
};

export type SpaceMember = {
  /** Identity user id: the `sub` apps already store as identitySub. */
  userId: string;
  email: string;
  displayName: string;
  role: SpaceRole;
};

export type SpaceDetail = { id: string; name: string; slug: string; members: SpaceMember[] };

const RANK: Record<SpaceRole, number> = { member: 1, admin: 2, owner: 3 };

function oid(id: string, what = "id") {
  if (!/^[a-f0-9]{24}$/i.test(id)) throw new AppError(`Invalid ${what}`, 400, "invalid_request");
  return new Types.ObjectId(id);
}

async function uniqueSlug(name: string) {
  const base = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "space";
  let slug = base;
  for (let n = 1; await Organization.exists({ slug }); n += 1) slug = `${base}-${n}`;
  return slug;
}

async function requireLiveSpace(spaceId: string) {
  const space = await Organization.findOne({ _id: oid(spaceId, "space"), status: "active" }).lean();
  if (!space) throw new AppError("Space not found", 404, "not_found");
  return space;
}

/** The viewer's role in a space; outsiders get the same 404 as a missing space. */
async function requireRole(spaceId: string, userId: string, min: SpaceRole): Promise<SpaceRole> {
  await requireLiveSpace(spaceId);
  const membership = await OrganizationMembership.findOne({
    organizationId: oid(spaceId, "space"),
    userId: oid(userId, "user"),
  }).lean();
  if (!membership) throw new AppError("Space not found", 404, "not_found");
  const role = membership.role as SpaceRole;
  if (RANK[role] < RANK[min]) throw new AppError("You don't have permission to do that", 403, "forbidden");
  return role;
}

async function ownerCount(spaceId: Types.ObjectId) {
  return OrganizationMembership.countDocuments({ organizationId: spaceId, role: "owner" });
}

export async function listSpacesForUser(userId: string): Promise<SpaceSummary[]> {
  const memberships = await OrganizationMembership.find({ userId: oid(userId, "user") }).lean();
  const spaces = await Organization.find({
    _id: { $in: memberships.map((m) => m.organizationId) },
    status: "active",
  }).sort({ name: 1 }).lean();
  const counts = await OrganizationMembership.aggregate<{ _id: Types.ObjectId; n: number }>([
    { $match: { organizationId: { $in: spaces.map((s) => s._id) } } },
    { $group: { _id: "$organizationId", n: { $sum: 1 } } },
  ]);
  const countById = new Map(counts.map((c) => [String(c._id), c.n]));
  const roleById = new Map(memberships.map((m) => [String(m.organizationId), m.role as SpaceRole]));
  return spaces.map((space) => ({
    id: String(space._id),
    name: space.name,
    slug: space.slug,
    role: roleById.get(String(space._id))!,
    memberCount: countById.get(String(space._id)) ?? 0,
  }));
}

export async function getSpace(spaceId: string): Promise<SpaceDetail> {
  const space = await requireLiveSpace(spaceId);
  const memberships = await OrganizationMembership.find({ organizationId: space._id }).lean();
  const users = await User.find({ _id: { $in: memberships.map((m) => m.userId) } })
    .select("email displayName status")
    .lean();
  const userById = new Map(users.map((u) => [String(u._id), u]));
  const members = memberships.flatMap((m): SpaceMember[] => {
    const user = userById.get(String(m.userId));
    // A disabled account keeps its seat but no app should treat it as a member.
    if (!user || user.status === "disabled") return [];
    return [{ userId: String(m.userId), email: user.email, displayName: user.displayName, role: m.role as SpaceRole }];
  });
  members.sort((a, b) => RANK[b.role] - RANK[a.role] || a.displayName.localeCompare(b.displayName));
  return { id: String(space._id), name: space.name, slug: space.slug, members };
}

/** A space as seen by one of its members. */
export async function getSpaceForMember(spaceId: string, userId: string): Promise<SpaceDetail & { role: SpaceRole }> {
  const role = await requireRole(spaceId, userId, "member");
  return { ...(await getSpace(spaceId)), role };
}

/**
 * Creates a space owned by `ownerId`. `members` (used when an app turns an
 * existing team into a space) must be existing, verified Identity users.
 */
export async function createSpace(input: {
  ownerId: string;
  name: string;
  members?: Array<{ userId: string; role: SpaceRole }>;
}): Promise<SpaceDetail> {
  const name = input.name.trim();
  if (!name || name.length > 80) throw new AppError("Give the space a name (up to 80 characters)", 400, "invalid_request");
  const owner = await User.findById(oid(input.ownerId, "user")).lean();
  if (!owner || !owner.emailVerified || owner.status !== "active") {
    throw new AppError("Only a verified account can create a space", 403, "forbidden");
  }

  const roles = new Map<string, SpaceRole>([[String(owner._id), "owner"]]);
  for (const member of input.members ?? []) {
    if (!roles.has(member.userId)) roles.set(member.userId, member.role);
  }
  const people = await User.find({
    _id: { $in: [...roles.keys()].map((id) => oid(id, "user")) },
    emailVerified: true,
    status: "active",
  }).select("_id").lean();
  const valid = new Set(people.map((p) => String(p._id)));

  const space = await Organization.create({ name, slug: await uniqueSlug(name), status: "active" });
  await OrganizationMembership.insertMany(
    [...roles].filter(([userId]) => valid.has(userId)).map(([userId, role]) => ({
      organizationId: space._id,
      userId: new Types.ObjectId(userId),
      role,
    })),
  );
  return getSpace(String(space._id));
}

export async function renameSpace(actorId: string, spaceId: string, name: string): Promise<SpaceDetail> {
  await requireRole(spaceId, actorId, "admin");
  const trimmed = name.trim();
  if (!trimmed || trimmed.length > 80) throw new AppError("Give the space a name (up to 80 characters)", 400, "invalid_request");
  await Organization.updateOne({ _id: oid(spaceId, "space") }, { $set: { name: trimmed } });
  return getSpace(spaceId);
}

/** Adds someone by the email of their (verified) Noirly account. */
export async function addMemberByEmail(
  actorId: string,
  spaceId: string,
  email: string,
  role: SpaceRole,
): Promise<SpaceDetail> {
  const actorRole = await requireRole(spaceId, actorId, "admin");
  if (role === "owner" && actorRole !== "owner") throw new AppError("Only an owner can add owners", 403, "forbidden");
  const user = await User.findOne({ email: normalizeEmail(email) }).lean();
  // Same answer whether the account is missing or unverified: no account probing.
  if (!user || !user.emailVerified || user.status !== "active") {
    throw new AppError("No verified Noirly account uses that email. Ask them to sign up first.", 404, "not_found");
  }
  const exists = await OrganizationMembership.exists({ organizationId: oid(spaceId, "space"), userId: user._id });
  if (exists) throw new AppError("They're already in this space", 409, "already_member");
  await OrganizationMembership.create({ organizationId: oid(spaceId, "space"), userId: user._id, role });
  return getSpace(spaceId);
}

export async function changeMemberRole(
  actorId: string,
  spaceId: string,
  targetId: string,
  role: SpaceRole,
): Promise<SpaceDetail> {
  const actorRole = await requireRole(spaceId, actorId, "admin");
  const space = oid(spaceId, "space");
  const target = await OrganizationMembership.findOne({ organizationId: space, userId: oid(targetId, "user") });
  if (!target) throw new AppError("They're not in this space", 404, "not_found");
  // Owners are made and unmade only by owners.
  if ((role === "owner" || target.role === "owner") && actorRole !== "owner") {
    throw new AppError("Only an owner can change an owner's role or make someone an owner", 403, "forbidden");
  }
  if (target.role === "owner" && role !== "owner" && (await ownerCount(space)) <= 1) {
    throw new AppError("A space needs at least one owner. Make someone else an owner first.", 409, "last_owner");
  }
  target.role = role;
  await target.save();
  return getSpace(spaceId);
}

/** Removes a member (admins), or leaves (anyone, for themselves). */
export async function removeMember(actorId: string, spaceId: string, targetId: string): Promise<void> {
  const self = actorId === targetId;
  const actorRole = await requireRole(spaceId, actorId, self ? "member" : "admin");
  const space = oid(spaceId, "space");
  const target = await OrganizationMembership.findOne({ organizationId: space, userId: oid(targetId, "user") });
  if (!target) throw new AppError("They're not in this space", 404, "not_found");
  if (!self && target.role === "owner" && actorRole !== "owner") {
    throw new AppError("Only an owner can remove an owner", 403, "forbidden");
  }
  if (target.role === "owner" && (await ownerCount(space)) <= 1) {
    const others = await OrganizationMembership.countDocuments({ organizationId: space, _id: { $ne: target._id } });
    if (others > 0) {
      throw new AppError("A space needs at least one owner. Make someone else an owner first.", 409, "last_owner");
    }
  }
  await target.deleteOne();
  // Nobody left: the space goes too.
  if (!(await OrganizationMembership.exists({ organizationId: space }))) {
    await Organization.updateOne({ _id: space }, { $set: { status: "disabled" } });
  }
}

/** Ends a space. Linked apps unlink their teams and keep them as they are. */
export async function deleteSpace(actorId: string, spaceId: string): Promise<void> {
  await requireRole(spaceId, actorId, "owner");
  const space = oid(spaceId, "space");
  await OrganizationMembership.deleteMany({ organizationId: space });
  await Organization.updateOne({ _id: space }, { $set: { status: "disabled" } });
}

/** Spaces a user belongs to, for an app acting on their behalf. */
export async function spacesForSubject(sub: string): Promise<SpaceSummary[]> {
  return listSpacesForUser(sub);
}

/**
 * Before an account is deleted: in spaces where it is the only owner but
 * others remain, the longest-standing admin (else member) becomes owner, so
 * the space isn't left with nobody able to manage it.
 */
export async function handOverOwnedSpaces(userId: Types.ObjectId): Promise<string[]> {
  const owned = await OrganizationMembership.find({ userId, role: "owner" }).lean();
  const changed: string[] = [];
  for (const membership of owned) {
    const space = membership.organizationId;
    if ((await ownerCount(space)) > 1) continue;
    const others = { organizationId: space, userId: { $ne: userId } };
    const pick =
      (await OrganizationMembership.findOne({ ...others, role: "admin" }).sort({ createdAt: 1 }).lean()) ??
      (await OrganizationMembership.findOne(others).sort({ createdAt: 1 }).lean());
    if (!pick) continue;
    await OrganizationMembership.updateOne({ _id: pick._id }, { $set: { role: "owner" } });
    changed.push(String(space));
  }
  return changed;
}

/** Spaces a user is in (to notify apps when they leave every one at once). */
export async function spaceIdsForUser(userId: Types.ObjectId): Promise<string[]> {
  return (await OrganizationMembership.find({ userId }).select("organizationId").lean()).map((m) =>
    String(m.organizationId),
  );
}
