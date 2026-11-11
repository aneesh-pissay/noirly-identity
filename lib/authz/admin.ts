import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { orgStream } from "@/lib/audit/chain";
import { recordEvent, type RequestMeta } from "@/lib/audit/event-log";
import { validConditions } from "@/lib/authz/validate";
import { validPermission, resourceMatches } from "@/lib/authz/engine";
import { AuthzRole, RoleAssignment, ServiceAccount } from "@/models/Authz";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { SpaceTeam } from "@/models/SpaceTeam";
import { canAdminister, roleIn } from "@/lib/spaces/space-service";
import type { Condition } from "@/lib/authz/conditions";

/**
 * Managing access in an organization: its roles, who holds them, and
 * members' attributes for conditions. Admins with the access area (owners
 * always). Every change goes in the organization's own event log
 * (`org:<id>`), with who did it: the permission audit trail.
 */

export type RoleView = { id: string; name: string; description: string; permissions: string[] };
export type AssignmentView = {
  id: string;
  roleId: string;
  subjectType: "user" | "team" | "service";
  subjectId: string;
  resource: string;
  conditions: Condition[];
  expiresAt: string | null;
  source: "direct" | "elevation";
  reason: string;
};

const oid = (id: string, what = "Item") => {
  if (!Types.ObjectId.isValid(id)) throw new AppError(`${what} not found`, 404, "not_found");
  return new Types.ObjectId(id);
};

export async function requireAccessAdmin(spaceId: string, actorId: string) {
  if (!(await roleIn(spaceId, actorId))) throw new AppError("Space not found", 404, "not_found");
  if (!(await canAdminister(spaceId, actorId, "access"))) throw new AppError("You don't have permission to do that", 403, "forbidden");
}

const roleView = (r: { _id: Types.ObjectId; name: string; description?: string | null; permissions: string[] }): RoleView => ({ id: String(r._id), name: r.name, description: r.description ?? "", permissions: [...r.permissions] });
export const assignmentView = (a: {
  _id: Types.ObjectId; roleId: Types.ObjectId; subjectType: string; subjectId: Types.ObjectId; resource?: string | null; conditions?: Condition[] | null; expiresAt?: Date | null; source?: string | null; reason?: string | null;
}): AssignmentView => ({
  id: String(a._id),
  roleId: String(a.roleId),
  subjectType: a.subjectType as AssignmentView["subjectType"],
  subjectId: String(a.subjectId),
  resource: a.resource ?? "*",
  conditions: (a.conditions ?? []).map((c) => ({ attribute: c.attribute, op: c.op, value: c.value })),
  expiresAt: a.expiresAt ? a.expiresAt.toISOString() : null,
  source: (a.source as AssignmentView["source"]) ?? "direct",
  reason: a.reason ?? "",
});

function audit(spaceId: string, actorId: string, action: Parameters<typeof recordEvent>[0]["action"], data: Record<string, unknown>, meta: RequestMeta = {}, subjectId: string | null = null) {
  return recordEvent({ action, stream: orgStream(spaceId), actorId, subjectId, request: meta, data: { ...data, organizationId: spaceId } });
}

export async function listAccess(actorId: string, spaceId: string) {
  if (!(await roleIn(spaceId, actorId))) throw new AppError("Space not found", 404, "not_found");
  const org = oid(spaceId, "Space");
  const [roles, assignments] = await Promise.all([
    AuthzRole.find({ organizationId: org }).sort({ name: 1 }).lean(),
    RoleAssignment.find({ organizationId: org }).sort({ createdAt: 1 }).lean(),
  ]);
  return { roles: roles.map(roleView), assignments: assignments.map(assignmentView) };
}

function cleanPermissions(permissions: string[]) {
  const out = [...new Set(permissions.map((p) => p.trim().toLowerCase()).filter(Boolean))];
  const bad = out.filter((p) => !validPermission(p));
  if (bad.length) throw new AppError(`Permissions look like "invoice:read", "invoice:*" or "*": ${bad.join(", ")}`, 400, "invalid_permission");
  if (out.length > 200) throw new AppError("Up to 200 permissions in a role", 400, "invalid_permission");
  return out;
}

/** Creates or updates a role (by id, or a new one). */
export async function saveRole(actorId: string, spaceId: string, input: { id?: string; name: string; description?: string; permissions: string[] }, meta: RequestMeta = {}): Promise<RoleView> {
  await requireAccessAdmin(spaceId, actorId);
  const name = input.name.trim();
  if (!name || name.length > 60) throw new AppError("Give the role a name (up to 60 characters)", 400, "invalid_request");
  const permissions = cleanPermissions(input.permissions);
  const org = oid(spaceId, "Space");
  try {
    const role = input.id
      ? await AuthzRole.findOneAndUpdate({ _id: oid(input.id, "Role"), organizationId: org }, { $set: { name, description: input.description ?? "", permissions } }, { returnDocument: "after" }).lean()
      : (await AuthzRole.create({ organizationId: org, name, description: input.description ?? "", permissions })).toObject();
    if (!role) throw new AppError("Role not found", 404, "not_found");
    await audit(spaceId, actorId, "authz.role_saved", { roleId: String(role._id), name, permissions, created: !input.id }, meta);
    return roleView(role);
  } catch (error) {
    if ((error as { code?: number }).code === 11000) throw new AppError("There's already a role with that name", 409, "duplicate_role");
    throw error;
  }
}

/** Deletes a role and every assignment of it. */
export async function deleteRole(actorId: string, spaceId: string, roleId: string, meta: RequestMeta = {}) {
  await requireAccessAdmin(spaceId, actorId);
  const role = await AuthzRole.findOneAndDelete({ _id: oid(roleId, "Role"), organizationId: oid(spaceId, "Space") }).lean();
  if (!role) throw new AppError("Role not found", 404, "not_found");
  const removed = await RoleAssignment.deleteMany({ roleId: role._id });
  await audit(spaceId, actorId, "authz.role_deleted", { roleId, name: role.name, assignmentsRemoved: removed.deletedCount }, meta);
}

/** The subject of an assignment must belong to the organization. */
async function assertSubject(spaceId: string, type: AssignmentView["subjectType"], id: string) {
  const org = oid(spaceId, "Space");
  const sid = oid(id, "Subject");
  const ok =
    type === "user" ? await OrganizationMembership.exists({ organizationId: org, userId: sid })
      : type === "team" ? await SpaceTeam.exists({ organizationId: org, _id: sid })
        : await ServiceAccount.exists({ organizationId: org, _id: sid, disabledAt: null });
  if (!ok) throw new AppError("Assign roles to people, teams or service accounts of this organization", 409, "not_in_space");
}

export async function assignRole(
  actorId: string,
  spaceId: string,
  input: { roleId: string; subjectType: AssignmentView["subjectType"]; subjectId: string; resource?: string; conditions?: Condition[]; expiresAt?: string | null; reason?: string; source?: "direct" | "elevation" },
  meta: RequestMeta = {},
  { skipAdminCheck = false } = {},
): Promise<AssignmentView> {
  if (!skipAdminCheck) await requireAccessAdmin(spaceId, actorId);
  const org = oid(spaceId, "Space");
  const role = await AuthzRole.findOne({ _id: oid(input.roleId, "Role"), organizationId: org }).lean();
  if (!role) throw new AppError("Role not found", 404, "not_found");
  await assertSubject(spaceId, input.subjectType, input.subjectId);
  const resource = (input.resource ?? "*").trim() || "*";
  if (resource !== "*" && !/^[a-z][a-z0-9_-]{0,40}\/(\*|[A-Za-z0-9_.:-]{1,120})$/.test(resource)) {
    throw new AppError('Resources look like "*", "project/*" or "project/42"', 400, "invalid_resource");
  }
  const conditions = validConditions(input.conditions ?? []);
  const expiresAt = input.expiresAt ? new Date(input.expiresAt) : null;
  if (expiresAt && (Number.isNaN(expiresAt.getTime()) || expiresAt <= new Date())) throw new AppError("The expiry must be in the future", 400, "invalid_request");
  const assignment = await RoleAssignment.create({
    organizationId: org,
    roleId: role._id,
    subjectType: input.subjectType,
    subjectId: oid(input.subjectId, "Subject"),
    resource,
    conditions,
    expiresAt,
    grantedBy: oid(actorId, "Actor"),
    source: input.source ?? "direct",
    reason: (input.reason ?? "").slice(0, 300),
  });
  await audit(spaceId, actorId, "authz.assigned", { assignmentId: String(assignment._id), role: role.name, subjectType: input.subjectType, subjectId: input.subjectId, resource, conditions, expiresAt: expiresAt?.toISOString() ?? null, source: input.source ?? "direct" }, meta, input.subjectType === "user" ? input.subjectId : null);
  return assignmentView(assignment.toObject());
}

export async function unassignRole(actorId: string, spaceId: string, assignmentId: string, meta: RequestMeta = {}) {
  await requireAccessAdmin(spaceId, actorId);
  const removed = await RoleAssignment.findOneAndDelete({ _id: oid(assignmentId, "Assignment"), organizationId: oid(spaceId, "Space") }).lean();
  if (!removed) throw new AppError("Assignment not found", 404, "not_found");
  await audit(spaceId, actorId, "authz.unassigned", { assignmentId, roleId: String(removed.roleId), subjectType: removed.subjectType, subjectId: String(removed.subjectId), resource: removed.resource }, meta, removed.subjectType === "user" ? String(removed.subjectId) : null);
}

/** What the organization records about a member, for conditions (department, region…). */
export async function setMemberAttributes(actorId: string, spaceId: string, userId: string, attributes: Record<string, string>, meta: RequestMeta = {}) {
  await requireAccessAdmin(spaceId, actorId);
  const clean: Record<string, string> = {};
  for (const [key, value] of Object.entries(attributes)) {
    if (!/^[a-z][a-z0-9_]{0,40}$/.test(key) || ["time", "weekday", "device", "acr", "country"].includes(key)) throw new AppError(`Invalid attribute: ${key}`, 400, "invalid_request");
    if (typeof value !== "string" || value.length > 100) throw new AppError(`Invalid value for ${key}`, 400, "invalid_request");
    if (value) clean[key] = value;
  }
  const result = await OrganizationMembership.updateOne({ organizationId: oid(spaceId, "Space"), userId: oid(userId, "Member") }, { $set: { attributes: clean } });
  if (!result.matchedCount) throw new AppError("They're not in this space", 404, "not_found");
  await audit(spaceId, actorId, "authz.attributes_set", { userId, attributes: clean }, meta, userId);
  return clean;
}

/** Assignments covering a resource (for the simulator's view of a resource). */
export function coversResource(pattern: string, resource: string | null) {
  return resourceMatches(pattern, resource);
}
