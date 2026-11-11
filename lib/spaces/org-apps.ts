import { Types } from "mongoose";
import { AppError, OAuthError } from "@/lib/api/errors";
import { Organization } from "@/models/Organization";
import { OAuthClient } from "@/models/OAuthClient";
import { SpaceTeam } from "@/models/SpaceTeam";
import { canAdminister, roleIn } from "@/lib/spaces/space-service";
import { teamsOf } from "@/lib/spaces/teams";

/**
 * Which Noirly apps an organization uses, and who in it may open them.
 * - `open` (the default): any app may be opened inside the organization.
 * - `listed`: only the apps it lists, each with who may open it: everyone,
 *   admins (and owners), or chosen teams (sub-team members count).
 * Applies when an app is opened inside the organization (organization
 * context, lib/oauth/org-context.ts), at sign-in and at every token exchange
 * and refresh. Apps are named by their `appKey`, so every environment of an
 * app follows the same rule. Managed by admins with the apps area.
 */

export type AppAccessRule = "everyone" | "admins" | "teams";
export type OrgApp = { appKey: string; name: string; access: AppAccessRule; teamIds: string[] };
export type OrgAppsView = { mode: "open" | "listed"; apps: OrgApp[]; available: Array<{ appKey: string; name: string }> };

type StoredApp = { appKey: string; access?: string | null; teamIds?: Types.ObjectId[] | null };

async function requireAppsAdmin(spaceId: string, actorId: string) {
  if (!(await roleIn(spaceId, actorId))) throw new AppError("Space not found", 404, "not_found");
  if (!(await canAdminister(spaceId, actorId, "apps"))) throw new AppError("You don't have permission to do that", 403, "forbidden");
}

async function appNames(appKeys: string[]) {
  const clients = await OAuthClient.find({ $or: [{ appKey: { $in: appKeys } }, { clientId: { $in: appKeys } }] }).select("clientId appKey name environment").lean();
  const names = new Map<string, string>();
  for (const c of clients) names.set(c.appKey ?? c.clientId, c.name);
  return names;
}

export async function getOrgApps(actorId: string, spaceId: string): Promise<OrgAppsView> {
  if (!(await roleIn(spaceId, actorId))) throw new AppError("Space not found", 404, "not_found");
  const org = await Organization.findById(new Types.ObjectId(spaceId)).select("appsMode apps").lean();
  const stored = (org?.apps ?? []) as StoredApp[];
  const active = await OAuthClient.find({ status: "active" }).select("clientId appKey name").lean();
  const available = new Map<string, string>();
  for (const c of active) available.set(c.appKey ?? c.clientId, c.name);
  const names = await appNames(stored.map((a) => a.appKey));
  return {
    mode: (org?.appsMode as "open" | "listed") ?? "open",
    apps: stored.map((a) => ({ appKey: a.appKey, name: names.get(a.appKey) ?? a.appKey, access: (a.access as AppAccessRule) ?? "everyone", teamIds: (a.teamIds ?? []).map(String) })),
    available: [...available].map(([appKey, name]) => ({ appKey, name })).sort((a, b) => a.name.localeCompare(b.name)),
  };
}

export async function setOrgAppsMode(actorId: string, spaceId: string, mode: "open" | "listed") {
  await requireAppsAdmin(spaceId, actorId);
  await Organization.updateOne({ _id: new Types.ObjectId(spaceId) }, { $set: { appsMode: mode } });
  return getOrgApps(actorId, spaceId);
}

/** Lists an app (or changes who may open it). */
export async function setOrgApp(actorId: string, spaceId: string, input: { appKey: string; access: AppAccessRule; teamIds?: string[] }) {
  await requireAppsAdmin(spaceId, actorId);
  if (!(await OAuthClient.exists({ $or: [{ appKey: input.appKey }, { clientId: input.appKey }] }))) throw new AppError("Unknown app", 404, "not_found");
  let teamIds: Types.ObjectId[] = [];
  if (input.access === "teams") {
    const ids = [...new Set(input.teamIds ?? [])].filter((id) => Types.ObjectId.isValid(id)).map((id) => new Types.ObjectId(id));
    const found = await SpaceTeam.countDocuments({ _id: { $in: ids }, organizationId: new Types.ObjectId(spaceId) });
    if (!ids.length || found !== ids.length) throw new AppError("Choose teams from this space", 400, "invalid_request");
    teamIds = ids;
  }
  const space = new Types.ObjectId(spaceId);
  await Organization.updateOne({ _id: space }, { $pull: { apps: { appKey: input.appKey } } });
  await Organization.updateOne({ _id: space }, { $push: { apps: { appKey: input.appKey, access: input.access, teamIds } } });
  return getOrgApps(actorId, spaceId);
}

export async function removeOrgApp(actorId: string, spaceId: string, appKey: string) {
  await requireAppsAdmin(spaceId, actorId);
  await Organization.updateOne({ _id: new Types.ObjectId(spaceId) }, { $pull: { apps: { appKey } } });
  return getOrgApps(actorId, spaceId);
}

/** May this person open this app inside this organization? */
export async function orgAllowsApp(organizationId: string, userId: string, client: { clientId: string; appKey?: string | null }): Promise<boolean> {
  const org = await Organization.findById(new Types.ObjectId(organizationId)).select("appsMode apps").lean();
  if (!org || (org.appsMode ?? "open") === "open") return true;
  const appKey = client.appKey ?? client.clientId;
  const entry = ((org.apps ?? []) as StoredApp[]).find((a) => a.appKey === appKey);
  if (!entry) return false;
  const access = (entry.access as AppAccessRule) ?? "everyone";
  if (access === "everyone") return true;
  const role = await roleIn(organizationId, userId);
  if (role === "owner" || role === "admin") return true;
  if (access === "admins") return false;
  const mine = new Set((await teamsOf(organizationId, userId)).map((t) => t.id));
  return (entry.teamIds ?? []).some((id) => mine.has(String(id)));
}

/** At the token endpoint: a grant scoped to an organization whose rules no longer admit this app or person ends. */
export async function assertOrgAllowsApp(organizationId: unknown, userId: unknown, client: { clientId: string; appKey?: string | null }) {
  if (!(await orgAllowsApp(String(organizationId), String(userId), client))) {
    throw new OAuthError("invalid_grant", "This organization doesn't allow this app for this account");
  }
}
