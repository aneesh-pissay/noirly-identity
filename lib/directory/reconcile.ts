import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { orgStream } from "@/lib/audit/chain";
import { recordEvent } from "@/lib/audit/event-log";
import { requireMembersAdmin } from "@/lib/directory/lifecycle";
import { emitLifecycle } from "@/lib/webhooks/lifecycle";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { SpaceDomain } from "@/models/SpaceDomain";
import { User } from "@/models/User";
import { UserEmail } from "@/models/UserEmail";

/**
 * Duplicate detection and provisioning reconciliation, for a space's admins:
 * - possible duplicates: accounts that look like the same person at the
 *   space's domains (the same address but for a `+tag`, or one account's
 *   confirmed additional address is another's sign-in address);
 * - unmanaged: members at the space's domains the directory doesn't know
 *   (no SCIM id), who the directory won't deactivate when they leave;
 * - outside: members whose address isn't at the space's domains (the space
 *   can't deactivate their account, only their membership).
 * `link` records a member's directory id by hand, so the directory manages them.
 */

export type DuplicateGroup = { key: string; reason: "plus_alias" | "additional_address"; accounts: Array<{ userId: string; email: string; member: boolean }> };

const canonical = (email: string) => {
  const [local, domain] = email.toLowerCase().split("@");
  return `${local!.split("+")[0]}@${domain}`;
};

export async function directoryReport(actorId: string, spaceId: string) {
  await requireMembersAdmin(spaceId, actorId);
  const space = new Types.ObjectId(spaceId);
  const domains = (await SpaceDomain.find({ organizationId: space, verifiedAt: { $ne: null } }).select("domain").lean()).map((d) => d.domain);
  const memberships = await OrganizationMembership.find({ organizationId: space }).select("userId role scimExternalId").lean<Array<{ userId: Types.ObjectId; role: string; scimExternalId?: string | null }>>();
  const memberIds = new Set(memberships.map((m) => String(m.userId)));
  const members = await User.find({ _id: { $in: memberships.map((m) => m.userId) } }).select("email displayName").lean();
  const at = (email: string) => domains.includes(email.split("@")[1] ?? "");

  // Everyone at the space's domains, members or not, for duplicates.
  const pattern = domains.length ? new RegExp(`@(${domains.map((d) => d.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})$`, "i") : null;
  const atDomains = pattern ? await User.find({ email: pattern }).select("email").limit(5000).lean() : [];
  const groups = new Map<string, Set<string>>();
  for (const u of atDomains) {
    const key = canonical(u.email);
    groups.set(key, (groups.get(key) ?? new Set()).add(String(u._id)));
  }
  const emailOf = new Map(atDomains.map((u) => [String(u._id), u.email]));
  const duplicates: DuplicateGroup[] = [...groups.entries()]
    .filter(([, ids]) => ids.size > 1)
    .map(([key, ids]) => ({ key, reason: "plus_alias" as const, accounts: [...ids].map((id) => ({ userId: id, email: emailOf.get(id)!, member: memberIds.has(id) })) }));
  if (atDomains.length) {
    const extra = await UserEmail.find({ email: { $in: atDomains.map((u) => u.email) }, verifiedAt: { $ne: null } }).select("userId email").lean();
    for (const e of extra) {
      const primary = atDomains.find((u) => u.email === e.email);
      if (!primary || String(primary._id) === String(e.userId)) continue;
      const other = await User.findById(e.userId).select("email").lean();
      if (!other) continue;
      duplicates.push({ key: e.email, reason: "additional_address", accounts: [{ userId: String(primary._id), email: primary.email, member: memberIds.has(String(primary._id)) }, { userId: String(other._id), email: other.email, member: memberIds.has(String(other._id)) }] });
    }
  }

  const byId = new Map(members.map((u) => [String(u._id), u]));
  const person = (m: (typeof memberships)[number]) => ({ userId: String(m.userId), email: byId.get(String(m.userId))?.email ?? "", name: byId.get(String(m.userId))?.displayName ?? "", role: m.role });
  return {
    domains,
    duplicates,
    unmanaged: memberships.filter((m) => !m.scimExternalId && at(byId.get(String(m.userId))?.email ?? "")).map(person),
    outside: memberships.filter((m) => !at(byId.get(String(m.userId))?.email ?? "")).map(person),
  };
}

/** Records a member's directory id by hand (reconciling an unmanaged member with the directory). */
export async function linkDirectoryId(actorId: string, spaceId: string, userId: string, externalId: string) {
  await requireMembersAdmin(spaceId, actorId);
  const space = new Types.ObjectId(spaceId);
  const id = externalId.trim().slice(0, 300);
  if (!id || !Types.ObjectId.isValid(userId)) throw new AppError("Give a member and their directory id", 400, "invalid_request");
  if (await OrganizationMembership.exists({ organizationId: space, scimExternalId: id, userId: { $ne: new Types.ObjectId(userId) } })) throw new AppError("Another member already has that directory id", 409, "conflict");
  const r = await OrganizationMembership.updateOne({ organizationId: space, userId: new Types.ObjectId(userId) }, { $set: { scimExternalId: id } });
  if (!r.matchedCount) throw new AppError("Not a member of this space", 404, "not_found");
  await recordEvent({ action: "directory.user_updated", stream: orgStream(spaceId), actorId, subjectId: userId, data: { organizationId: spaceId, linkedExternalId: true } });
  await emitLifecycle("membership.changed", { userId, organizationId: spaceId, data: { change: "linked_to_directory" } });
}
