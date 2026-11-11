import { Types } from "mongoose";
import { OAuthError } from "@/lib/api/errors";
import { Organization } from "@/models/Organization";
import { OrganizationMembership } from "@/models/OrganizationMembership";

/**
 * Organization context. An app can sign someone in to one of their
 * organizations (spaces): `organization=<id or slug>` on the authorization
 * request, or `organization=select` for Identity's picker. The tokens it gets
 * are scoped to that organization: the ID token, UserInfo, JWT access tokens
 * and introspection carry `org_id`, `org_slug` and `org_role`, and refreshes
 * stay in it. Leave the organization and the next refresh fails. To switch,
 * the app runs the authorization request again (silently, with
 * `prompt=none`) naming another organization.
 */

export type OrgContext = { id: string; slug: string; name: string; role: string };

/** The organization an authorization request names, if the person belongs to it. */
export async function resolveOrganization(userId: string, value: string): Promise<OrgContext | null> {
  const filter = /^[a-f0-9]{24}$/i.test(value) ? { _id: new Types.ObjectId(value) } : { slug: value.trim().toLowerCase() };
  const org = await Organization.findOne({ ...filter, status: "active" }).select("slug name").lean();
  if (!org) return null;
  const membership = await OrganizationMembership.findOne({ organizationId: org._id, userId: new Types.ObjectId(userId) }).select("role").lean();
  if (!membership) return null;
  return { id: String(org._id), slug: org.slug, name: org.name, role: membership.role };
}

/**
 * The claims for tokens scoped to an organization, checked live: someone who
 * has left (or whose organization is gone) gets `invalid_grant`, so a refresh
 * can't carry them on in it.
 */
export async function orgClaims(organizationId: unknown, userId: unknown): Promise<{ org_id: string; org_slug: string; org_role: string }> {
  const org = await resolveOrganization(String(userId), String(organizationId));
  if (!org) throw new OAuthError("invalid_grant", "No longer a member of that organization");
  return { org_id: org.id, org_slug: org.slug, org_role: org.role };
}

/** The `organizations` claim (scope `organizations`): every organization the person is in. */
export async function organizationsClaim(userId: unknown): Promise<Array<{ id: string; slug: string; name: string; role: string }>> {
  const memberships = await OrganizationMembership.find({ userId: new Types.ObjectId(String(userId)) }).select("organizationId role").lean();
  const orgs = await Organization.find({ _id: { $in: memberships.map((m) => m.organizationId) }, status: "active" }).select("slug name").sort({ name: 1 }).lean();
  const roles = new Map(memberships.map((m) => [String(m.organizationId), m.role]));
  return orgs.map((o) => ({ id: String(o._id), slug: o.slug, name: o.name, role: roles.get(String(o._id)) ?? "member" }));
}

/** Organizations to offer on the picker. */
export async function organizationChoices(userId: string) {
  return organizationsClaim(userId);
}
