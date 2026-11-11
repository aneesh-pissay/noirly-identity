import { Types } from "mongoose";
import { AppError, OAuthError } from "@/lib/api/errors";
import { normalizeEmail } from "@/lib/auth/user-mapper";
import { Organization } from "@/models/Organization";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { OAuthClient } from "@/models/OAuthClient";
import { User } from "@/models/User";

/**
 * Who may use an app (per client, so each environment can differ):
 * - `anyone` with a Noirly account (the default);
 * - `spaces`: members of any of the chosen spaces (organizations);
 * - `allowlist`: only the listed accounts.
 * Checked when someone signs in to the app (app/api/oauth/authorize) and again
 * whenever it gets tokens (code exchange, refresh, mobile), so taking someone
 * out of a space ends their access at the app's next refresh.
 */

export type AccessMode = "anyone" | "spaces" | "allowlist";
export type AccessPolicy = { mode: AccessMode; spaceIds: string[]; userIds: string[] };

type PolicyHolder = { accessPolicy?: { mode?: string | null; spaceIds?: unknown[] | null; userIds?: unknown[] | null } | null };

export function policyOf(client: PolicyHolder): AccessPolicy {
  const p = client.accessPolicy;
  return {
    mode: (p?.mode as AccessMode) ?? "anyone",
    spaceIds: (p?.spaceIds ?? []).map(String),
    userIds: (p?.userIds ?? []).map(String),
  };
}

export async function mayUseApp(client: PolicyHolder, userId: string | Types.ObjectId): Promise<boolean> {
  const policy = policyOf(client);
  const id = String(userId);
  if (policy.mode === "anyone") return true;
  if (policy.mode === "allowlist") return policy.userIds.includes(id);
  if (!policy.spaceIds.length) return false;
  return Boolean(
    await OrganizationMembership.exists({
      userId: new Types.ObjectId(id),
      organizationId: { $in: policy.spaceIds.map((s) => new Types.ObjectId(s)) },
    }),
  );
}

/** At the token endpoint: a grant for someone the app no longer admits is refused. */
export async function assertMayUseApp(client: PolicyHolder, userId: string | Types.ObjectId) {
  if (!(await mayUseApp(client, userId))) {
    throw new OAuthError("invalid_grant", "This account doesn't have access to this app");
  }
}

/**
 * Sets an app's policy. Spaces are named by their slugs; allowlisted people by
 * the emails of verified accounts. Anything unknown is refused as a whole.
 */
export async function setAccessPolicy(clientId: string, input: { mode: AccessMode; spaces?: string[]; emails?: string[] }) {
  if (!(await OAuthClient.exists({ clientId }))) throw new AppError("Unknown OAuth client", 404, "not_found");
  let spaceIds: Types.ObjectId[] = [];
  let userIds: Types.ObjectId[] = [];
  if (input.mode === "spaces") {
    const slugs = [...new Set((input.spaces ?? []).map((s) => s.trim().toLowerCase()).filter(Boolean))];
    if (!slugs.length) throw new AppError("Choose at least one space", 400, "validation_error");
    const spaces = await Organization.find({ slug: { $in: slugs }, status: "active" }).select("_id").lean();
    if (spaces.length !== slugs.length) throw new AppError("One of those spaces doesn't exist", 400, "unknown_space");
    spaceIds = spaces.map((s) => s._id);
  }
  if (input.mode === "allowlist") {
    const emails = [...new Set((input.emails ?? []).map(normalizeEmail).filter(Boolean))];
    if (!emails.length) throw new AppError("List at least one person", 400, "validation_error");
    if (emails.length > 500) throw new AppError("Up to 500 people; use a space for more", 400, "validation_error");
    const users = await User.find({ email: { $in: emails }, emailVerified: true, status: "active" }).select("_id").lean();
    if (users.length !== emails.length) {
      throw new AppError("Everyone on the list needs a verified Noirly account. Check the addresses.", 400, "unknown_user");
    }
    userIds = users.map((u) => u._id);
  }
  await OAuthClient.updateOne({ clientId }, { $set: { accessPolicy: { mode: input.mode, spaceIds, userIds } } });
  return describePolicy({ accessPolicy: { mode: input.mode, spaceIds, userIds } });
}

/** The policy in words, for the admin screen. */
export async function describePolicy(client: PolicyHolder) {
  const policy = policyOf(client);
  if (policy.mode === "anyone") return { mode: policy.mode, summary: "Anyone with a Noirly account", spaces: [] as string[], people: [] as string[] };
  if (policy.mode === "spaces") {
    const spaces = await Organization.find({ _id: { $in: policy.spaceIds.map((s) => new Types.ObjectId(s)) } }).select("slug name").lean();
    return { mode: policy.mode, summary: `Members of ${spaces.map((s) => s.name).join(", ") || "no spaces"}`, spaces: spaces.map((s) => s.slug), people: [] };
  }
  const users = await User.find({ _id: { $in: policy.userIds.map((u) => new Types.ObjectId(u)) } }).select("email").lean();
  return { mode: policy.mode, summary: `${users.length} ${users.length === 1 ? "person" : "people"}`, spaces: [], people: users.map((u) => u.email) };
}
