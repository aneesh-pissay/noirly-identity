import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { getCurrentUser } from "@/lib/auth/auth-service";
import { normalizeEmail } from "@/lib/auth/user-mapper";
import { OAuthClient } from "@/models/OAuthClient";
import { User } from "@/models/User";
import type { PublicUser } from "@/types";

/**
 * App owners: people other than the global admin who manage their own app.
 * Owners are set per app (every environment of it, by `appKey`). An owner can
 * see and change their app's settings: redirects, logout URIs, environments,
 * secrets, status and co-owners. Registering new apps and deleting them stay
 * with admins, as do API grants (lib/oauth/resources.ts).
 */

export type AppManager = { user: PublicUser; isAdmin: boolean };

const isAdmin = (user: PublicUser) => user.roles.includes("admin");

/** Admins manage every app; owners only theirs. Anyone else gets the same 404 as a missing app. */
export async function requireClientManager(sessionToken: string | null, clientId: string): Promise<AppManager> {
  const user = await getCurrentUser(sessionToken);
  if (!user) throw new AppError("Authentication required", 401, "unauthorized");
  if (isAdmin(user)) return { user, isAdmin: true };
  const owns = await OAuthClient.exists({ clientId, ownerIds: new Types.ObjectId(user.id) });
  if (!owns) throw new AppError("Unknown OAuth client", 404, "not_found");
  return { user, isAdmin: false };
}

/** Anyone signed in who is an admin or owns at least one app may open /clients. */
export async function requireAnyClientManager(sessionToken: string | null): Promise<AppManager> {
  const user = await getCurrentUser(sessionToken);
  if (!user) throw new AppError("Authentication required", 401, "unauthorized");
  if (isAdmin(user)) return { user, isAdmin: true };
  if (!(await ownsAnyApp(user.id))) throw new AppError("Admin access required", 403, "forbidden");
  return { user, isAdmin: false };
}

export async function ownsAnyApp(userId: string) {
  return Boolean(await OAuthClient.exists({ ownerIds: new Types.ObjectId(userId) }));
}

/** The filter for the apps a manager may see. */
export function clientsVisibleTo(manager: AppManager) {
  return manager.isAdmin ? {} : { ownerIds: new Types.ObjectId(manager.user.id) };
}

/**
 * Sets an app's owners, by the emails of verified Noirly accounts, on every
 * environment of it. Unknown or unverified addresses are refused all together
 * with one answer, so this can't be used to probe for accounts.
 */
export async function setAppOwners(clientId: string, emails: string[]) {
  const client = await OAuthClient.findOne({ clientId }).select("appKey clientId").lean();
  if (!client) throw new AppError("Unknown OAuth client", 404, "not_found");
  const wanted = [...new Set(emails.map(normalizeEmail).filter(Boolean))];
  if (wanted.length > 20) throw new AppError("An app can have up to 20 owners", 400, "validation_error");
  const users = await User.find({ email: { $in: wanted }, emailVerified: true, status: "active" }).select("_id email").lean();
  if (users.length !== wanted.length) {
    throw new AppError("Every owner needs a verified Noirly account. Check the addresses, or ask them to sign up first.", 400, "unknown_owner");
  }
  const appKey = client.appKey ?? client.clientId;
  await OAuthClient.updateMany({ $or: [{ appKey }, { clientId: appKey }] }, { $set: { ownerIds: users.map((u) => u._id) } });
  return users.map((u) => ({ userId: String(u._id), email: u.email }));
}

/** Owners as people, for the apps a list shows. */
export async function ownerEmails(ownerIds: string[]) {
  if (!ownerIds.length) return {};
  const users = await User.find({ _id: { $in: ownerIds.map((id) => new Types.ObjectId(id)) } }).select("email").lean();
  return Object.fromEntries(users.map((u) => [String(u._id), u.email])) as Record<string, string>;
}
