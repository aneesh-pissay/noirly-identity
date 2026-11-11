import { resolveTxt } from "node:dns/promises";
import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { generateSecureToken } from "@/lib/security/crypto";
import { Organization } from "@/models/Organization";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { SpaceDomain } from "@/models/SpaceDomain";
import { User } from "@/models/User";
import { UserEmail } from "@/models/UserEmail";
import { roleIn, type SpaceRole } from "@/lib/spaces/space-service";

/**
 * Verified business domains. A space's owner claims a domain by publishing a
 * TXT record (`_noirly-verify.<domain>` = `noirly-verification=<token>`); once
 * Identity sees it, the domain is the space's, and no other space can claim
 * it. Its policy:
 * - `invite_only`: claimed (for single sign-on enforcement later), but joining
 *   still takes an invitation;
 * - `auto_join`: anyone whose confirmed address is at that domain may join as
 *   a member, without an invitation.
 */

export type DomainPolicy = "invite_only" | "auto_join";
export type DomainView = {
  domain: string;
  verified: boolean;
  policy: DomainPolicy;
  /** What to publish to verify it. */
  txtName: string;
  txtValue: string;
};

const DOMAIN = /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

/** Addresses anyone can get: no business owns these. */
const PERSONAL_DOMAINS = new Set([
  "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com", "live.com", "msn.com",
  "icloud.com", "me.com", "mac.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "mail.com", "zoho.com",
  "yandex.com", "rediffmail.com", "fastmail.com", "hey.com",
]);

type TxtResolver = (name: string) => Promise<string[][]>;
let resolver: TxtResolver = resolveTxt;
/** Tests: answer DNS lookups without the network. */
export function setTxtResolver(next: TxtResolver | null) {
  resolver = next ?? resolveTxt;
}

const view = (d: { domain: string; verifiedAt?: Date | null; policy?: string | null; verificationToken: string }): DomainView => ({
  domain: d.domain,
  verified: Boolean(d.verifiedAt),
  policy: (d.policy as DomainPolicy) ?? "invite_only",
  txtName: `_noirly-verify.${d.domain}`,
  txtValue: `noirly-verification=${d.verificationToken}`,
});

/** Owners, or admins delegated the domains area explicitly (not admins by default: a domain is a lot of power). */
export async function requireDomainOwner(spaceId: string, actorId: string) {
  const role = await roleIn(spaceId, actorId);
  if (!role) throw new AppError("Space not found", 404, "not_found");
  if (role === "owner") return;
  const membership = await OrganizationMembership.findOne({ organizationId: new Types.ObjectId(spaceId), userId: new Types.ObjectId(actorId) }).select("adminAreas").lean();
  if (role === "admin" && Array.isArray(membership?.adminAreas) && membership.adminAreas.includes("domains")) return;
  throw new AppError("Only an owner can manage the space's domains", 403, "forbidden");
}

export function normalizeDomain(input: string) {
  const domain = input.trim().toLowerCase().replace(/\.$/, "");
  if (!DOMAIN.test(domain)) throw new AppError("That isn't a domain name", 400, "invalid_domain");
  if (PERSONAL_DOMAINS.has(domain)) throw new AppError("That's a personal email provider; claim your own domain", 400, "personal_domain");
  return domain;
}

export async function listDomains(actorId: string, spaceId: string): Promise<DomainView[]> {
  const role = await roleIn(spaceId, actorId);
  if (!role) throw new AppError("Space not found", 404, "not_found");
  const domains = await SpaceDomain.find({ organizationId: new Types.ObjectId(spaceId) }).sort({ domain: 1 }).lean();
  return domains.map(view);
}

export async function addDomain(actorId: string, spaceId: string, input: string): Promise<DomainView> {
  await requireDomainOwner(spaceId, actorId);
  const domain = normalizeDomain(input);
  if (await SpaceDomain.exists({ domain, verifiedAt: { $ne: null } })) {
    throw new AppError("Another space has already verified that domain", 409, "domain_taken");
  }
  const space = new Types.ObjectId(spaceId);
  const existing = await SpaceDomain.findOne({ organizationId: space, domain }).lean();
  if (existing) return view(existing);
  const created = await SpaceDomain.create({ organizationId: space, domain, verificationToken: generateSecureToken(18) });
  return view(created);
}

/** Looks up the TXT record; verified once it holds the token. */
export async function verifyDomain(actorId: string, spaceId: string, input: string): Promise<DomainView> {
  await requireDomainOwner(spaceId, actorId);
  const domain = normalizeDomain(input);
  const record = await SpaceDomain.findOne({ organizationId: new Types.ObjectId(spaceId), domain });
  if (!record) throw new AppError("Add the domain first", 404, "not_found");
  if (record.verifiedAt) return view(record);
  let found = false;
  try {
    const answers = await resolver(`_noirly-verify.${domain}`);
    found = answers.some((chunks) => chunks.join("").trim() === `noirly-verification=${record.verificationToken}`);
  } catch {
    found = false;
  }
  record.lastCheckedAt = new Date();
  if (!found) {
    await record.save();
    throw new AppError(`No matching TXT record at _noirly-verify.${domain} yet. DNS changes can take a while to appear.`, 409, "not_verified");
  }
  if (await SpaceDomain.exists({ domain, verifiedAt: { $ne: null }, _id: { $ne: record._id } })) {
    throw new AppError("Another space has already verified that domain", 409, "domain_taken");
  }
  record.verifiedAt = new Date();
  await record.save();
  return view(record);
}

export async function setDomainPolicy(actorId: string, spaceId: string, input: string, policy: DomainPolicy): Promise<DomainView> {
  await requireDomainOwner(spaceId, actorId);
  const domain = normalizeDomain(input);
  const filter = { organizationId: new Types.ObjectId(spaceId), domain };
  const existing = await SpaceDomain.findOne(filter).select("verifiedAt").lean();
  if (!existing) throw new AppError("Domain not found", 404, "not_found");
  // Checked before anything changes: an unverified domain never becomes a way in.
  if (policy === "auto_join" && !existing.verifiedAt) throw new AppError("Verify the domain before letting people join through it", 409, "not_verified");
  const record = await SpaceDomain.findOneAndUpdate(filter, { $set: { policy } }, { returnDocument: "after" }).lean();
  return view(record!);
}

export async function removeDomain(actorId: string, spaceId: string, input: string) {
  await requireDomainOwner(spaceId, actorId);
  await SpaceDomain.deleteOne({ organizationId: new Types.ObjectId(spaceId), domain: normalizeDomain(input) });
}

/** The domains of someone's confirmed addresses: primary and verified extras. */
export async function confirmedDomainsOf(userId: string): Promise<string[]> {
  const id = new Types.ObjectId(userId);
  const [user, extras] = await Promise.all([
    User.findById(id).select("email emailVerified").lean(),
    UserEmail.find({ userId: id, verifiedAt: { $ne: null } }).select("email").lean(),
  ]);
  const emails = [...(user?.emailVerified ? [user.email] : []), ...extras.map((e) => e.email)];
  return [...new Set(emails.map((e) => e.split("@")[1]!).filter(Boolean))];
}

/** Spaces someone may join without an invitation, through a verified auto-join domain. */
export async function joinableSpaces(userId: string) {
  const domains = await confirmedDomainsOf(userId);
  if (!domains.length) return [];
  const records = await SpaceDomain.find({ domain: { $in: domains }, verifiedAt: { $ne: null }, policy: "auto_join" }).lean();
  const mine = new Set((await OrganizationMembership.find({ userId: new Types.ObjectId(userId) }).select("organizationId").lean()).map((m) => String(m.organizationId)));
  const candidates = records.filter((r) => !mine.has(String(r.organizationId)));
  const spaces = await Organization.find({ _id: { $in: candidates.map((c) => c.organizationId) }, status: "active" }).select("name").lean();
  return spaces.map((s) => ({ id: String(s._id), name: s.name, domain: candidates.find((c) => String(c.organizationId) === String(s._id))!.domain }));
}

/** Joins as a member through a verified auto-join domain. */
export async function joinThroughDomain(userId: string, spaceId: string): Promise<SpaceRole> {
  const eligible = await joinableSpaces(userId);
  if (!eligible.some((s) => s.id === spaceId)) throw new AppError("Space not found", 404, "not_found");
  const joined = await OrganizationMembership.updateOne(
    { organizationId: new Types.ObjectId(spaceId), userId: new Types.ObjectId(userId) },
    { $setOnInsert: { role: "member" } },
    { upsert: true },
  );
  if (joined.upsertedCount) {
    const { membershipChanged } = await import("@/lib/spaces/space-service");
    await membershipChanged(userId, spaceId, "joined", "member");
  }
  return "member";
}
