import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { applySessionPolicy, validatePolicy } from "@/lib/sessions/lifetime";
import type { SessionPolicy } from "@/lib/sessions/lifetime-choices";
import { Organization } from "@/models/Organization";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { canAdminister, roleIn } from "@/lib/spaces/space-service";

/**
 * An organization's security policies, set by admins with the settings area:
 * - a second step at sign-in (`requireMfa`, lib/spaces/space-service.ts);
 * - allowed sign-in methods: opening an app inside the organization needs a
 *   sign-in that used one of them (say, a passkey or Google, but not a
 *   password); anything else is asked to sign in again;
 * - session lifetimes: members' sessions last no longer than the
 *   organization allows (the strictest of theirs and every organization's,
 *   lib/sessions/lifetime.ts).
 */

/** Ways to sign in an organization can allow (second steps aren't among them). */
export const PRIMARY_METHODS = ["password", "passkey", "google", "apple", "microsoft", "github", "magic_link", "email_code", "sso"] as const;
export type PrimaryMethod = (typeof PRIMARY_METHODS)[number];

export type OrgSecurity = { requireMfa: boolean; allowedMethods: PrimaryMethod[]; sessionPolicy: SessionPolicy };

export async function getOrgSecurity(actorId: string, spaceId: string): Promise<OrgSecurity> {
  if (!(await roleIn(spaceId, actorId))) throw new AppError("Space not found", 404, "not_found");
  const org = await Organization.findById(new Types.ObjectId(spaceId)).select("requireMfa allowedMethods sessionPolicy").lean();
  return {
    requireMfa: Boolean(org?.requireMfa),
    allowedMethods: (org?.allowedMethods ?? []) as PrimaryMethod[],
    sessionPolicy: { idleSeconds: org?.sessionPolicy?.idleSeconds ?? null, absoluteSeconds: org?.sessionPolicy?.absoluteSeconds ?? null },
  };
}

export async function setOrgSecurity(actorId: string, spaceId: string, input: { allowedMethods?: string[]; sessionPolicy?: SessionPolicy }): Promise<OrgSecurity> {
  if (!(await roleIn(spaceId, actorId))) throw new AppError("Space not found", 404, "not_found");
  if (!(await canAdminister(spaceId, actorId, "settings"))) throw new AppError("You don't have permission to do that", 403, "forbidden");
  const set: Record<string, unknown> = {};
  if (input.allowedMethods) {
    const unknown = input.allowedMethods.filter((m) => !(PRIMARY_METHODS as readonly string[]).includes(m));
    if (unknown.length) throw new AppError(`Unknown sign-in methods: ${unknown.join(", ")}`, 400, "invalid_request");
    set.allowedMethods = [...new Set(input.allowedMethods)];
  }
  if (input.sessionPolicy) set.sessionPolicy = validatePolicy(input.sessionPolicy);
  await Organization.updateOne({ _id: new Types.ObjectId(spaceId) }, { $set: set });
  // Members' live sessions follow a tighter limit at once.
  if (input.sessionPolicy) {
    const members = await OrganizationMembership.find({ organizationId: new Types.ObjectId(spaceId) }).select("userId").lean();
    for (const m of members) await applySessionPolicy(String(m.userId));
  }
  return getOrgSecurity(actorId, spaceId);
}

/** Did this sign-in use a method the organization allows? (Any, when it lists none.) */
export async function signInMeetsOrgMethods(organizationId: string, sessionMethods: readonly string[]): Promise<{ ok: boolean; allowed: string[] }> {
  const org = await Organization.findById(new Types.ObjectId(organizationId)).select("allowedMethods").lean();
  const allowed = org?.allowedMethods ?? [];
  if (!allowed.length) return { ok: true, allowed };
  return { ok: sessionMethods.some((m) => allowed.includes(m)), allowed };
}
