import { Types } from "mongoose";
import { AuthzRole, RoleAssignment } from "@/models/Authz";
import { Organization } from "@/models/Organization";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { teamsOf } from "@/lib/spaces/teams";
import { failedCondition, type CheckContext, type Condition } from "@/lib/authz/conditions";

/**
 * The authorization engine. Default deny: something is allowed only when an
 * assignment grants it. An assignment counts when
 * - it's for the person, a team they're in (sub-team members included), or
 *   the service account asking;
 * - it hasn't expired;
 * - its role holds the permission (exactly, `kind:*`, or `*`);
 * - its resource covers the resource asked about (`*`, `project/*`, `project/42`);
 * - every condition holds (lib/authz/conditions.ts).
 * `explain` says which assignments matched and why the others didn't: what
 * policy simulation shows.
 */

export type Subject = { type: "user"; id: string } | { type: "service"; id: string };

export type Decision = {
  allowed: boolean;
  /** Assignments that granted it. */
  grantedBy: Array<{ assignmentId: string; role: string; via: string; resource: string; expiresAt: string | null }>;
  /** Assignments that could have, and why they didn't. */
  notApplied: Array<{ assignmentId: string; role: string; via: string; reason: string }>;
  /** Why it's denied, when it is. */
  reason: string | null;
};

export function permissionMatches(granted: string, wanted: string) {
  if (granted === "*" || granted === wanted) return true;
  if (granted.endsWith(":*")) return wanted.startsWith(granted.slice(0, -1));
  return false;
}

export function resourceMatches(pattern: string, resource: string | null | undefined) {
  if (pattern === "*") return true;
  if (!resource) return false;
  if (pattern.endsWith("/*")) return resource.startsWith(pattern.slice(0, -1));
  return pattern === resource;
}

const PERMISSION = /^(\*|[a-z][a-z0-9_.-]{0,40}:(\*|[a-z][a-z0-9_.-]{0,40}))$/;
export function validPermission(permission: string) {
  return PERMISSION.test(permission);
}

/** Who an assignment can be about for this subject: themselves, and (for people) their teams. */
async function subjectKeys(orgId: string, subject: Subject) {
  if (subject.type === "service") return { keys: [{ subjectType: "service" as const, subjectId: new Types.ObjectId(subject.id) }], via: new Map([[subject.id, "the service account"]]), attributes: {} as Record<string, string> };
  const membership = await OrganizationMembership.findOne({ organizationId: new Types.ObjectId(orgId), userId: new Types.ObjectId(subject.id) }).select("attributes").lean();
  if (!membership) return null;
  const teams = await teamsOf(orgId, subject.id);
  const via = new Map<string, string>([[subject.id, "directly"], ...teams.map((t) => [t.id, `team ${t.name}`] as [string, string])]);
  // Lean documents give a Map field back as a plain object.
  const attributes = { ...((membership.attributes as unknown as Record<string, string> | undefined) ?? {}) };
  return {
    keys: [{ subjectType: "user" as const, subjectId: new Types.ObjectId(subject.id) }, ...teams.map((t) => ({ subjectType: "team" as const, subjectId: new Types.ObjectId(t.id) }))],
    via,
    attributes,
  };
}

async function load(orgId: string, subject: Subject) {
  const who = await subjectKeys(orgId, subject);
  if (!who) return null;
  const org = await Organization.findById(new Types.ObjectId(orgId)).select("timeZone").lean();
  const assignments = await RoleAssignment.find({ organizationId: new Types.ObjectId(orgId), $or: who.keys }).lean();
  const roles = new Map((await AuthzRole.find({ _id: { $in: assignments.map((a) => a.roleId) } }).lean()).map((r) => [String(r._id), r]));
  return { who, assignments, roles, timeZone: (org as { timeZone?: string } | null)?.timeZone };
}

/** Can this subject do this, on this resource, now? With the reasons. */
export async function explain(orgId: string, subject: Subject, permission: string, resource: string | null = null, context: CheckContext = {}): Promise<Decision> {
  const loaded = await load(orgId, subject);
  if (!loaded) return { allowed: false, grantedBy: [], notApplied: [], reason: "Not a member of this organization" };
  const now = context.now ?? new Date();
  const grantedBy: Decision["grantedBy"] = [];
  const notApplied: Decision["notApplied"] = [];
  for (const a of loaded.assignments) {
    const role = loaded.roles.get(String(a.roleId));
    if (!role) continue;
    if (!role.permissions.some((p) => permissionMatches(p, permission))) continue;
    const base = { assignmentId: String(a._id), role: role.name, via: loaded.who.via.get(String(a.subjectId)) ?? a.subjectType };
    if (a.expiresAt && a.expiresAt <= now) { notApplied.push({ ...base, reason: `expired ${a.expiresAt.toISOString()}` }); continue; }
    if (!resourceMatches(a.resource ?? "*", resource)) { notApplied.push({ ...base, reason: `only for ${a.resource}` }); continue; }
    const failure = (a.conditions as Condition[]).map((c) => failedCondition(c, loaded.who.attributes, { ...context, now, timeZone: context.timeZone ?? loaded.timeZone })).find(Boolean);
    if (failure) { notApplied.push({ ...base, reason: failure }); continue; }
    grantedBy.push({ ...base, resource: a.resource ?? "*", expiresAt: a.expiresAt ? a.expiresAt.toISOString() : null });
  }
  const allowed = grantedBy.length > 0;
  return {
    allowed,
    grantedBy,
    notApplied,
    reason: allowed ? null : notApplied.length ? "Every assignment that could grant it has a condition, resource or expiry that doesn't fit" : "No role grants it (denied by default)",
  };
}

export async function can(orgId: string, subject: Subject, permission: string, resource: string | null = null, context: CheckContext = {}) {
  return (await explain(orgId, subject, permission, resource, context)).allowed;
}

/**
 * Everything the subject may do right now, for token claims: plain
 * permissions for assignments on every resource, and `permission@resource`
 * for those on some.
 */
export async function effectivePermissions(orgId: string, subject: Subject, context: CheckContext = {}): Promise<string[]> {
  const loaded = await load(orgId, subject);
  if (!loaded) return [];
  const now = context.now ?? new Date();
  const out = new Set<string>();
  for (const a of loaded.assignments) {
    const role = loaded.roles.get(String(a.roleId));
    if (!role) continue;
    if (a.expiresAt && a.expiresAt <= now) continue;
    if ((a.conditions as Condition[]).some((c) => failedCondition(c, loaded.who.attributes, { ...context, now, timeZone: context.timeZone ?? loaded.timeZone }))) continue;
    for (const p of role.permissions) out.add(a.resource && a.resource !== "*" ? `${p}@${a.resource}` : p);
  }
  return [...out].sort();
}
