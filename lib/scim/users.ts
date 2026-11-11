import { Types } from "mongoose";
import { orgStream } from "@/lib/audit/chain";
import { recordEvent } from "@/lib/audit/event-log";
import { normalizeEmail } from "@/lib/auth/user-mapper";
import { DeactivatedMembership, deactivateMember, forgetDeactivated, isManagedAddress, reactivateMember } from "@/lib/directory/lifecycle";
import { listResponse, parseFilter, patchOps, SCHEMA, ScimError, truthy } from "@/lib/scim/http";
import { getEnv } from "@/lib/config/env";
import { emitLifecycle } from "@/lib/webhooks/lifecycle";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { User, type UserDocument } from "@/models/User";
import { UserEmail } from "@/models/UserEmail";

/**
 * SCIM Users for one space. A "user" here is an account with a membership
 * (active) or a deactivated membership (inactive) in the space.
 *
 * Provisioning is for addresses at the space's verified domains only: the
 * space owns those identities, so it may create accounts for them, adopt
 * existing ones, and deactivate them. Creating someone who already has an
 * account adopts it (reconciliation) rather than making a duplicate: matched
 * by address, or by a confirmed additional address on another account.
 */

type Member = { userId: Types.ObjectId; active: boolean; externalId: string | null; createdAt?: Date };

const base = () => `${getEnv().APP_URL.replace(/\/+$/, "")}/api/scim/v2`;

function toScim(user: Pick<UserDocument, "_id" | "email" | "firstName" | "lastName" | "displayName"> & { createdAt?: Date; updatedAt?: Date }, member: Member) {
  return {
    schemas: [SCHEMA.user],
    id: String(user._id),
    ...(member.externalId ? { externalId: member.externalId } : {}),
    userName: user.email,
    name: { givenName: user.firstName, familyName: user.lastName, formatted: `${user.firstName} ${user.lastName}`.trim() },
    displayName: user.displayName,
    emails: [{ value: user.email, type: "work", primary: true }],
    active: member.active,
    meta: { resourceType: "User", created: (user.createdAt ?? new Date()).toISOString(), lastModified: (user.updatedAt ?? new Date()).toISOString(), location: `${base()}/Users/${String(user._id)}` },
  };
}

async function memberOf(space: Types.ObjectId, userId: Types.ObjectId): Promise<Member | null> {
  const m = await OrganizationMembership.findOne({ organizationId: space, userId }).select("userId scimExternalId").lean<{ userId: Types.ObjectId; scimExternalId?: string | null }>();
  if (m) return { userId, active: true, externalId: m.scimExternalId ?? null };
  const d = await DeactivatedMembership.findOne({ organizationId: space, userId }).lean();
  return d ? { userId, active: false, externalId: d.scimExternalId ?? null } : null;
}

async function allMembers(space: Types.ObjectId): Promise<Member[]> {
  const [active, inactive] = await Promise.all([
    OrganizationMembership.find({ organizationId: space }).select("userId scimExternalId").lean<Array<{ userId: Types.ObjectId; scimExternalId?: string | null }>>(),
    DeactivatedMembership.find({ organizationId: space }).select("userId scimExternalId").lean(),
  ]);
  return [...active.map((m) => ({ userId: m.userId, active: true, externalId: m.scimExternalId ?? null })), ...inactive.map((m) => ({ userId: m.userId, active: false, externalId: m.scimExternalId ?? null }))];
}

const oid = (id: string) => {
  if (!Types.ObjectId.isValid(id)) throw new ScimError(404, "User not found");
  return new Types.ObjectId(id);
};

export async function getScimUser(organizationId: string, id: string) {
  const space = new Types.ObjectId(organizationId);
  const userId = oid(id);
  const member = await memberOf(space, userId);
  const user = member ? await User.findById(userId).lean() : null;
  if (!member || !user) throw new ScimError(404, "User not found");
  return toScim(user, member);
}

export async function listScimUsers(organizationId: string, filterText: string | null, startIndex: number, count: number) {
  const space = new Types.ObjectId(organizationId);
  let members = await allMembers(space);
  const filter = parseFilter(filterText);
  let users = await User.find({ _id: { $in: members.map((m) => m.userId) } }).sort({ createdAt: 1 }).lean();
  if (filter) {
    const v = filter.value.toLowerCase();
    if (filter.attr === "username" || filter.attr === "emails.value" || filter.attr.startsWith("emails[")) {
      const target = filter.attr.startsWith("emails[") ? (/value eq "([^"]*)"/i.exec(filter.attr)?.[1] ?? v).toLowerCase() : v;
      users = users.filter((u) => u.email === target);
    } else if (filter.attr === "externalid") {
      members = members.filter((m) => m.externalId === filter.value);
      const ids = new Set(members.map((m) => String(m.userId)));
      users = users.filter((u) => ids.has(String(u._id)));
    } else if (filter.attr === "id") {
      users = users.filter((u) => String(u._id) === filter.value);
    } else {
      throw new ScimError(400, `Filtering on ${filter.attr} isn't supported`, "invalidFilter");
    }
  }
  const byId = new Map(members.map((m) => [String(m.userId), m]));
  const page = users.slice(startIndex - 1, startIndex - 1 + count);
  return listResponse(page.map((u) => toScim(u, byId.get(String(u._id))!)), users.length, startIndex);
}

function readUser(body: Record<string, unknown>) {
  const emails = Array.isArray(body.emails) ? (body.emails as Array<{ value?: unknown; primary?: unknown }>) : [];
  const primary = emails.find((e) => truthy(e.primary)) ?? emails[0];
  const raw = typeof body.userName === "string" ? body.userName : typeof primary?.value === "string" ? primary.value : "";
  const email = normalizeEmail(raw);
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new ScimError(400, "userName must be the person's email address", "invalidValue");
  const name = (body.name ?? {}) as { givenName?: unknown; familyName?: unknown };
  const str = (v: unknown, max = 100) => (typeof v === "string" ? v.trim().slice(0, max) : "");
  return {
    email,
    externalId: str(body.externalId, 300) || null,
    firstName: str(name.givenName),
    lastName: str(name.familyName),
    displayName: str(body.displayName, 150),
    active: body.active === undefined ? true : truthy(body.active),
  };
}

/** Finds who an address already belongs to: the account with it, or with it confirmed as an additional address. */
async function existingAccount(email: string) {
  const direct = await User.findOne({ email });
  if (direct) return direct;
  const other = await UserEmail.findOne({ email, verifiedAt: { $ne: null } }).lean();
  return other ? User.findById(other.userId) : null;
}

export async function createScimUser(organizationId: string, body: Record<string, unknown>) {
  const space = new Types.ObjectId(organizationId);
  const input = readUser(body);
  if (!(await isManagedAddress(space, input.email))) throw new ScimError(400, "Only addresses at the space's verified domains can be provisioned", "invalidValue");
  if (input.externalId) {
    const taken = await OrganizationMembership.exists({ organizationId: space, scimExternalId: input.externalId });
    if (taken || (await DeactivatedMembership.exists({ organizationId: space, scimExternalId: input.externalId }))) throw new ScimError(409, "A user with that externalId already exists", "uniqueness");
  }

  let user = await existingAccount(input.email);
  let created = false;
  if (user) {
    const member = await memberOf(space, user._id);
    // Already provisioned from the directory under another id: a real conflict.
    if (member?.externalId && member.externalId !== input.externalId) throw new ScimError(409, "That user is already provisioned", "uniqueness");
    if (member && !member.active && input.active) await reactivateMember(organizationId, String(user._id), { actorId: null, via: "scim" });
  } else {
    const firstName = input.firstName || input.email.split("@")[0]!.slice(0, 100);
    const lastName = input.lastName || "User";
    user = await User.create({ email: input.email, passwordHash: null, firstName, lastName, displayName: input.displayName || `${firstName} ${lastName}`, emailVerified: true, status: "active", roles: ["user"] });
    created = true;
    await recordEvent({ action: "account.registered", subjectId: user._id, data: { method: "scim", organizationId } });
  }

  const joined = await OrganizationMembership.updateOne({ organizationId: space, userId: user._id }, { $setOnInsert: { role: "member" }, $set: { scimExternalId: input.externalId } }, { upsert: true });
  await recordEvent({ action: "directory.user_provisioned", stream: orgStream(organizationId), actorId: null, subjectId: user._id, data: { organizationId, accountCreated: created, adopted: !created } });
  if (created) await emitLifecycle("user.created", { userId: String(user._id), organizationId, data: { via: "scim" } });
  if (joined.upsertedCount) await emitLifecycle("membership.changed", { userId: String(user._id), organizationId, data: { change: "joined", role: "member", via: "scim" } });
  if (!input.active) await deactivateMember(organizationId, String(user._id), { actorId: null, via: "scim" }, "Provisioned inactive by the directory");
  return getScimUser(organizationId, String(user._id));
}

async function applyChanges(organizationId: string, userId: Types.ObjectId, changes: { firstName?: string; lastName?: string; displayName?: string; externalId?: string | null; active?: boolean }) {
  const space = new Types.ObjectId(organizationId);
  const member = await memberOf(space, userId);
  const user = member ? await User.findById(userId) : null;
  if (!member || !user) throw new ScimError(404, "User not found");
  const fields: string[] = [];
  // Profile fields only for identities the space owns.
  if (await isManagedAddress(space, user.email)) {
    if (changes.firstName && changes.firstName !== user.firstName) { user.firstName = changes.firstName; fields.push("firstName"); }
    if (changes.lastName && changes.lastName !== user.lastName) { user.lastName = changes.lastName; fields.push("lastName"); }
    if (changes.displayName && changes.displayName !== user.displayName) { user.displayName = changes.displayName; fields.push("displayName"); }
    if (fields.length) await user.save();
  }
  if (changes.externalId !== undefined && changes.externalId !== member.externalId) {
    if (member.active) await OrganizationMembership.updateOne({ organizationId: space, userId }, { $set: { scimExternalId: changes.externalId } });
    else await DeactivatedMembership.updateOne({ organizationId: space, userId }, { $set: { scimExternalId: changes.externalId } });
  }
  if (fields.length) {
    await recordEvent({ action: "directory.user_updated", stream: orgStream(organizationId), actorId: null, subjectId: userId, data: { organizationId, fields } });
    await emitLifecycle("user.updated", { userId: String(userId), organizationId, data: { fields, via: "scim" } });
  }
  if (changes.active === false && member.active) await deactivateMember(organizationId, String(userId), { actorId: null, via: "scim" }, "Deactivated by the directory");
  if (changes.active === true && !member.active) await reactivateMember(organizationId, String(userId), { actorId: null, via: "scim" });
}

export async function replaceScimUser(organizationId: string, id: string, body: Record<string, unknown>) {
  const input = readUser(body);
  await applyChanges(organizationId, oid(id), { firstName: input.firstName, lastName: input.lastName, displayName: input.displayName, externalId: input.externalId, active: input.active });
  return getScimUser(organizationId, id);
}

export async function patchScimUser(organizationId: string, id: string, body: Record<string, unknown>) {
  const changes: Parameters<typeof applyChanges>[2] = {};
  const set = (path: string, value: unknown) => {
    const p = path.toLowerCase();
    if (p === "active") changes.active = truthy(value);
    else if (p === "name.givenname") changes.firstName = String(value ?? "").slice(0, 100);
    else if (p === "name.familyname") changes.lastName = String(value ?? "").slice(0, 100);
    else if (p === "displayname") changes.displayName = String(value ?? "").slice(0, 150);
    else if (p === "externalid") changes.externalId = value ? String(value).slice(0, 300) : null;
    else if (p === "name" && value && typeof value === "object") {
      const n = value as { givenName?: unknown; familyName?: unknown };
      if (n.givenName !== undefined) set("name.givenName", n.givenName);
      if (n.familyName !== undefined) set("name.familyName", n.familyName);
    }
    // Other attributes (emails, userName, enterprise extension…) are the person's own here, and ignored.
  };
  for (const op of patchOps(body)) {
    if (op.op === "remove") {
      if (op.path?.toLowerCase() === "externalid") changes.externalId = null;
      continue;
    }
    if (op.path) set(op.path, op.value);
    else if (op.value && typeof op.value === "object") for (const [k, v] of Object.entries(op.value as Record<string, unknown>)) set(k, v);
  }
  await applyChanges(organizationId, oid(id), changes);
  return getScimUser(organizationId, id);
}

/** DELETE: deactivated (locking an owned identity) and then removed from the space for good. */
export async function deleteScimUser(organizationId: string, id: string) {
  const space = new Types.ObjectId(organizationId);
  const userId = oid(id);
  const member = await memberOf(space, userId);
  if (!member) throw new ScimError(404, "User not found");
  if (member.active) await deactivateMember(organizationId, id, { actorId: null, via: "scim" }, "Removed by the directory");
  await forgetDeactivated(organizationId, id);
}
