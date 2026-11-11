import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { SpaceTeam } from "@/models/SpaceTeam";
import { canAdminister, roleIn } from "@/lib/spaces/space-service";

/**
 * Teams inside a space, nested up to MAX_DEPTH levels. A team's members are
 * people already in the space. Membership flows upward: someone in "Design /
 * Brand" is also in "Design", so an app checking "is this person in Design?"
 * gets yes for the whole subtree (`teamsOf`). Managed by admins with the
 * members area (lib/spaces/space-service.ts).
 */

export const MAX_DEPTH = 5;

export type TeamView = { id: string; name: string; parentId: string | null; memberIds: string[] };

const view = (t: { _id: Types.ObjectId; name: string; parentId?: Types.ObjectId | null; memberIds?: Types.ObjectId[] }): TeamView => ({
  id: String(t._id),
  name: t.name,
  parentId: t.parentId ? String(t.parentId) : null,
  memberIds: (t.memberIds ?? []).map(String),
});

const oid = (id: string, what: string) => {
  if (!Types.ObjectId.isValid(id)) throw new AppError(`${what} not found`, 404, "not_found");
  return new Types.ObjectId(id);
};

async function requireViewer(spaceId: string, actorId: string) {
  if (!(await roleIn(spaceId, actorId))) throw new AppError("Space not found", 404, "not_found");
}

async function requireManager(spaceId: string, actorId: string) {
  await requireViewer(spaceId, actorId);
  if (!(await canAdminister(spaceId, actorId, "members"))) throw new AppError("You don't have permission to do that", 403, "forbidden");
}

async function teamIn(spaceId: string, teamId: string) {
  const team = await SpaceTeam.findOne({ _id: oid(teamId, "Team"), organizationId: oid(spaceId, "Space") });
  if (!team) throw new AppError("Team not found", 404, "not_found");
  return team;
}

/** The chain from a team up to the top, the team first. */
async function ancestors(spaceId: string, teamId: Types.ObjectId | null) {
  const chain: Types.ObjectId[] = [];
  let current = teamId;
  while (current && chain.length <= MAX_DEPTH + 1) {
    chain.push(current);
    const parent = await SpaceTeam.findOne({ _id: current, organizationId: oid(spaceId, "Space") }).select("parentId").lean();
    current = parent?.parentId ?? null;
  }
  return chain;
}

/** How deep the subtree under a team goes (1 for a team with no children). */
async function subtreeDepth(teamId: Types.ObjectId): Promise<number> {
  const children = await SpaceTeam.find({ parentId: teamId }).select("_id").lean();
  if (!children.length) return 1;
  return 1 + Math.max(...(await Promise.all(children.map((c) => subtreeDepth(c._id)))));
}

export async function listTeams(actorId: string, spaceId: string): Promise<TeamView[]> {
  await requireViewer(spaceId, actorId);
  return (await SpaceTeam.find({ organizationId: oid(spaceId, "Space") }).sort({ name: 1 }).lean()).map(view);
}

function cleanName(name: string) {
  const trimmed = name.trim();
  if (!trimmed || trimmed.length > 80) throw new AppError("Give the team a name (up to 80 characters)", 400, "invalid_request");
  return trimmed;
}

export async function createTeam(actorId: string, spaceId: string, input: { name: string; parentId?: string | null }): Promise<TeamView> {
  await requireManager(spaceId, actorId);
  const parent = input.parentId ? (await teamIn(spaceId, input.parentId))._id : null;
  if (parent && (await ancestors(spaceId, parent)).length >= MAX_DEPTH) {
    throw new AppError(`Teams nest at most ${MAX_DEPTH} deep`, 409, "too_deep");
  }
  try {
    return view(await SpaceTeam.create({ organizationId: oid(spaceId, "Space"), name: cleanName(input.name), parentId: parent }));
  } catch (error) {
    if ((error as { code?: number }).code === 11000) throw new AppError("There's already a team with that name there", 409, "duplicate_team");
    throw error;
  }
}

/** Renames a team, or moves it under another (never under itself or its own sub-teams). */
export async function updateTeam(actorId: string, spaceId: string, teamId: string, input: { name?: string; parentId?: string | null }): Promise<TeamView> {
  await requireManager(spaceId, actorId);
  const team = await teamIn(spaceId, teamId);
  if (input.name !== undefined) team.name = cleanName(input.name);
  if (input.parentId !== undefined) {
    const parent = input.parentId ? (await teamIn(spaceId, input.parentId))._id : null;
    if (parent) {
      const chain = await ancestors(spaceId, parent);
      if (chain.some((id) => id.equals(team._id))) throw new AppError("A team can't go inside itself or one of its own teams", 409, "cycle");
      if (chain.length + (await subtreeDepth(team._id)) > MAX_DEPTH) throw new AppError(`Teams nest at most ${MAX_DEPTH} deep`, 409, "too_deep");
    }
    team.parentId = parent;
  }
  try {
    await team.save();
  } catch (error) {
    if ((error as { code?: number }).code === 11000) throw new AppError("There's already a team with that name there", 409, "duplicate_team");
    throw error;
  }
  return view(team);
}

/** Deletes a team; its sub-teams move up to its parent. */
export async function deleteTeam(actorId: string, spaceId: string, teamId: string) {
  await requireManager(spaceId, actorId);
  const team = await teamIn(spaceId, teamId);
  await SpaceTeam.updateMany({ parentId: team._id }, { $set: { parentId: team.parentId ?? null } });
  await team.deleteOne();
}

/** Adds or removes people (who must be in the space). */
export async function setTeamMember(actorId: string, spaceId: string, teamId: string, userId: string, member: boolean): Promise<TeamView> {
  await requireManager(spaceId, actorId);
  const team = await teamIn(spaceId, teamId);
  const user = oid(userId, "Member");
  if (member && !(await OrganizationMembership.exists({ organizationId: team.organizationId, userId: user }))) {
    throw new AppError("Only people in the space can join its teams", 409, "not_in_space");
  }
  const updated = await SpaceTeam.findOneAndUpdate({ _id: team._id }, member ? { $addToSet: { memberIds: user } } : { $pull: { memberIds: user } }, { returnDocument: "after" }).lean();
  return view(updated!);
}

/**
 * The teams someone is in, inherited upward: direct teams and every team
 * above them. What apps get to decide access by team.
 */
export async function teamsOf(spaceId: string, userId: string): Promise<Array<{ id: string; name: string; direct: boolean }>> {
  const direct = await SpaceTeam.find({ organizationId: oid(spaceId, "Space"), memberIds: oid(userId, "Member") }).select("_id").lean();
  const all = await SpaceTeam.find({ organizationId: oid(spaceId, "Space") }).select("name parentId").lean();
  const byId = new Map(all.map((t) => [String(t._id), t]));
  const result = new Map<string, boolean>();
  for (const d of direct) {
    result.set(String(d._id), true);
    let parent = byId.get(String(d._id))?.parentId;
    for (let guard = 0; parent && guard < MAX_DEPTH + 1; guard += 1) {
      if (!result.has(String(parent))) result.set(String(parent), false);
      parent = byId.get(String(parent))?.parentId;
    }
  }
  return [...result].map(([id, isDirect]) => ({ id, name: byId.get(id)?.name ?? "", direct: isDirect })).sort((a, b) => a.name.localeCompare(b.name));
}

/** Someone left the space: they leave its teams too. */
export async function removeFromAllTeams(spaceId: Types.ObjectId, userId: Types.ObjectId) {
  await SpaceTeam.updateMany({ organizationId: spaceId, memberIds: userId }, { $pull: { memberIds: userId } });
}
