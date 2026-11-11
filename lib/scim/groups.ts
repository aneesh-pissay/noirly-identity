import { Types } from "mongoose";
import { orgStream } from "@/lib/audit/chain";
import { recordEvent } from "@/lib/audit/event-log";
import { getEnv } from "@/lib/config/env";
import { listResponse, parseFilter, patchOps, SCHEMA, ScimError } from "@/lib/scim/http";
import { emitLifecycle } from "@/lib/webhooks/lifecycle";
import { Organization } from "@/models/Organization";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { SpaceTeam } from "@/models/SpaceTeam";
import { User } from "@/models/User";

/**
 * SCIM Groups are the space's teams (directory group sync). Members must be
 * members of the space; anyone else in a group is ignored. Groups named in
 * the space's `scimAdminGroups` make their members admins; everyone else
 * provisioned stays a member. Owners are never changed.
 */

type Team = { _id: Types.ObjectId; organizationId: Types.ObjectId; name: string; scimExternalId?: string | null; memberIds: Types.ObjectId[]; createdAt?: Date; updatedAt?: Date };

const base = () => `${getEnv().APP_URL.replace(/\/+$/, "")}/api/scim/v2`;

async function toScim(team: Team) {
  const users = await User.find({ _id: { $in: team.memberIds } }).select("email").lean();
  return {
    schemas: [SCHEMA.group],
    id: String(team._id),
    ...(team.scimExternalId ? { externalId: team.scimExternalId } : {}),
    displayName: team.name,
    members: users.map((u) => ({ value: String(u._id), display: u.email, $ref: `${base()}/Users/${String(u._id)}` })),
    meta: { resourceType: "Group", created: (team.createdAt ?? new Date()).toISOString(), lastModified: (team.updatedAt ?? new Date()).toISOString(), location: `${base()}/Groups/${String(team._id)}` },
  };
}

const oid = (id: string) => {
  if (!Types.ObjectId.isValid(id)) throw new ScimError(404, "Group not found");
  return new Types.ObjectId(id);
};

async function findTeam(organizationId: string, id: string) {
  const team = await SpaceTeam.findOne({ _id: oid(id), organizationId: new Types.ObjectId(organizationId) }).lean<Team>();
  if (!team) throw new ScimError(404, "Group not found");
  return team;
}

/** Only the space's members can be in its teams. */
async function membersOnly(space: Types.ObjectId, ids: string[]) {
  const valid = ids.filter((id) => Types.ObjectId.isValid(id)).map((id) => new Types.ObjectId(id));
  const members = await OrganizationMembership.find({ organizationId: space, userId: { $in: valid } }).select("userId").lean();
  return members.map((m) => m.userId);
}

const memberValues = (value: unknown): string[] =>
  (Array.isArray(value) ? value : value ? [value] : []).map((m) => (typeof m === "object" && m ? String((m as { value?: unknown }).value ?? "") : String(m))).filter(Boolean);

/** Recomputes roles from the admin groups (for these people, or everyone when null). */
export async function syncRoles(organizationId: string, userIds: Types.ObjectId[] | null) {
  const space = new Types.ObjectId(organizationId);
  const org = await Organization.findById(space).select("scimAdminGroups").lean<{ scimAdminGroups?: string[] }>();
  const adminGroups = org?.scimAdminGroups ?? [];
  if (!adminGroups.length) return;
  const adminTeams = await SpaceTeam.find({ organizationId: space, name: { $in: adminGroups } }).select("memberIds").lean();
  const admins = new Set(adminTeams.flatMap((t) => t.memberIds.map(String)));
  // Only directory-provisioned members follow groups; people added by hand keep their role.
  const filter: Record<string, unknown> = { organizationId: space, role: { $in: ["admin", "member"] }, scimExternalId: { $nin: [null, ""] } };
  if (userIds) filter.userId = { $in: userIds };
  for (const m of await OrganizationMembership.find(filter).select("userId role").lean()) {
    const role = admins.has(String(m.userId)) ? "admin" : "member";
    if (role === m.role) continue;
    await OrganizationMembership.updateOne({ _id: m._id }, { $set: { role } });
    await emitLifecycle("membership.changed", { userId: String(m.userId), organizationId, data: { change: "role_changed", role, via: "scim" } });
  }
}

async function changed(organizationId: string, team: Team, before: Types.ObjectId[], after: Types.ObjectId[]) {
  const b = new Set(before.map(String));
  const a = new Set(after.map(String));
  const added = [...a].filter((x) => !b.has(x));
  const removed = [...b].filter((x) => !a.has(x));
  if (!added.length && !removed.length) return;
  await recordEvent({ action: "directory.group_synced", stream: orgStream(organizationId), actorId: null, subjectId: null, data: { organizationId, teamId: String(team._id), added, removed } });
  for (const id of [...added, ...removed]) await emitLifecycle("membership.changed", { userId: id, organizationId, data: { change: added.includes(id) ? "team_added" : "team_removed", teamId: String(team._id), via: "scim" } });
  await syncRoles(organizationId, [...added, ...removed].map((x) => new Types.ObjectId(x)));
}

export async function listScimGroups(organizationId: string, filterText: string | null, startIndex: number, count: number, excludeMembers: boolean) {
  const space = new Types.ObjectId(organizationId);
  const filter = parseFilter(filterText);
  const query: Record<string, unknown> = { organizationId: space };
  if (filter) {
    if (filter.attr === "displayname") query.name = filter.value;
    else if (filter.attr === "externalid") query.scimExternalId = filter.value;
    else if (filter.attr === "id" && Types.ObjectId.isValid(filter.value)) query._id = new Types.ObjectId(filter.value);
    else throw new ScimError(400, `Filtering on ${filter.attr} isn't supported`, "invalidFilter");
  }
  const total = await SpaceTeam.countDocuments(query);
  const teams = await SpaceTeam.find(query).sort({ createdAt: 1 }).skip(startIndex - 1).limit(count).lean<Team[]>();
  const resources = await Promise.all(teams.map(async (t) => {
    const g = await toScim(t);
    if (excludeMembers) delete (g as { members?: unknown }).members;
    return g;
  }));
  return listResponse(resources, total, startIndex);
}

export async function getScimGroup(organizationId: string, id: string) {
  return toScim(await findTeam(organizationId, id));
}

export async function createScimGroup(organizationId: string, body: Record<string, unknown>) {
  const space = new Types.ObjectId(organizationId);
  const name = typeof body.displayName === "string" ? body.displayName.trim().slice(0, 100) : "";
  if (!name) throw new ScimError(400, "displayName is required", "invalidValue");
  if (await SpaceTeam.exists({ organizationId: space, parentId: null, name })) throw new ScimError(409, "A group with that name already exists", "uniqueness");
  const members = await membersOnly(space, memberValues(body.members));
  const team = await SpaceTeam.create({ organizationId: space, name, parentId: null, memberIds: members, scimExternalId: typeof body.externalId === "string" ? body.externalId.slice(0, 300) : null });
  const doc = team.toObject() as Team;
  await changed(organizationId, doc, [], members);
  return toScim(doc);
}

export async function replaceScimGroup(organizationId: string, id: string, body: Record<string, unknown>) {
  const team = await findTeam(organizationId, id);
  const space = new Types.ObjectId(organizationId);
  const name = typeof body.displayName === "string" && body.displayName.trim() ? body.displayName.trim().slice(0, 100) : team.name;
  const members = await membersOnly(space, memberValues(body.members));
  await SpaceTeam.updateOne({ _id: team._id }, { $set: { name, memberIds: members, ...(typeof body.externalId === "string" ? { scimExternalId: body.externalId.slice(0, 300) } : {}) } });
  await changed(organizationId, team, team.memberIds, members);
  return getScimGroup(organizationId, id);
}

export async function patchScimGroup(organizationId: string, id: string, body: Record<string, unknown>) {
  const team = await findTeam(organizationId, id);
  const space = new Types.ObjectId(organizationId);
  let members = team.memberIds.map(String);
  let name = team.name;
  let externalId = team.scimExternalId ?? null;
  for (const op of patchOps(body)) {
    const path = op.path?.toLowerCase() ?? "";
    // Entra removes one member as: path `members[value eq "<id>"]`.
    const one = /^members\[value eq "([^"]+)"\]$/i.exec(op.path ?? "")?.[1];
    if (path === "members" || one || (!op.path && op.value && typeof op.value === "object" && "members" in (op.value as object))) {
      const values = one ? [one] : memberValues(op.path ? op.value : (op.value as { members?: unknown }).members);
      if (op.op === "add") members = [...new Set([...members, ...values])];
      else if (op.op === "remove") members = op.value === undefined && !one ? [] : members.filter((m) => !values.includes(m));
      else members = values;
    } else if (path === "displayname" || (!op.path && op.value && typeof op.value === "object" && "displayName" in (op.value as object))) {
      const v = op.path ? op.value : (op.value as { displayName?: unknown }).displayName;
      if (typeof v === "string" && v.trim()) name = v.trim().slice(0, 100);
    } else if (path === "externalid") {
      externalId = op.op === "remove" ? null : String(op.value ?? "").slice(0, 300) || null;
    }
  }
  const valid = await membersOnly(space, members);
  await SpaceTeam.updateOne({ _id: team._id }, { $set: { name, memberIds: valid, scimExternalId: externalId } });
  await changed(organizationId, team, team.memberIds, valid);
  return getScimGroup(organizationId, id);
}

export async function deleteScimGroup(organizationId: string, id: string) {
  const team = await findTeam(organizationId, id);
  await SpaceTeam.updateMany({ parentId: team._id }, { $set: { parentId: null } });
  await SpaceTeam.deleteOne({ _id: team._id });
  await changed(organizationId, team, team.memberIds, []);
}
