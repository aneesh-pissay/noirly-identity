import { Schema, Types, model, models, type Model } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { orgStream } from "@/lib/audit/chain";
import { recordEvent } from "@/lib/audit/event-log";
import { requireDomainOwner } from "@/lib/spaces/domains";
import { generateSecureToken, hashToken } from "@/lib/security/crypto";
import { consumeRateLimit } from "@/lib/security/shared-rate-limit";
import { Organization } from "@/models/Organization";

/**
 * SCIM bearer tokens: one per directory connection (say, "Entra provisioning"),
 * shown once, stored hashed. Owners (or admins with the domains area) make
 * and revoke them: provisioning creates and locks accounts at the space's
 * domains, as powerful as owning those domains.
 */

const MAX_TOKENS = 5;
const PREFIX = "scim_";

type TokenDoc = { _id: Types.ObjectId; organizationId: Types.ObjectId; name: string; tokenHash: string; createdBy: Types.ObjectId; lastUsedAt: Date | null; revokedAt: Date | null; createdAt: Date };
const tokenSchema = new Schema<TokenDoc>(
  {
    organizationId: { type: Schema.Types.ObjectId, required: true, index: true },
    name: { type: String, required: true, trim: true },
    tokenHash: { type: String, required: true, unique: true },
    createdBy: { type: Schema.Types.ObjectId, required: true },
    lastUsedAt: { type: Date, default: null },
    revokedAt: { type: Date, default: null },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);
export const ScimToken: Model<TokenDoc> = (models.ScimToken as never) || model("ScimToken", tokenSchema, "scim_tokens");

export type ScimTokenView = { id: string; name: string; createdAt: string; lastUsedAt: string | null };
const view = (t: TokenDoc): ScimTokenView => ({ id: String(t._id), name: t.name, createdAt: t.createdAt.toISOString(), lastUsedAt: t.lastUsedAt ? t.lastUsedAt.toISOString() : null });

export async function listScimTokens(actorId: string, spaceId: string) {
  await requireDomainOwner(spaceId, actorId);
  const org = await Organization.findById(new Types.ObjectId(spaceId)).select("scimAdminGroups").lean<{ scimAdminGroups?: string[] }>();
  const tokens = await ScimToken.find({ organizationId: new Types.ObjectId(spaceId), revokedAt: null }).sort({ createdAt: -1 }).lean<TokenDoc[]>();
  return { tokens: tokens.map(view), adminGroups: org?.scimAdminGroups ?? [] };
}

export async function createScimToken(actorId: string, spaceId: string, name: string): Promise<ScimTokenView & { token: string }> {
  await requireDomainOwner(spaceId, actorId);
  const space = new Types.ObjectId(spaceId);
  const label = name.trim();
  if (!label || label.length > 80) throw new AppError("Name the connection (up to 80 characters)", 400, "invalid_request");
  if ((await ScimToken.countDocuments({ organizationId: space, revokedAt: null })) >= MAX_TOKENS) throw new AppError(`Up to ${MAX_TOKENS} provisioning tokens`, 400, "too_many");
  const token = `${PREFIX}${generateSecureToken(32)}`;
  const created = await ScimToken.create({ organizationId: space, name: label, tokenHash: hashToken(token), createdBy: new Types.ObjectId(actorId) });
  await recordEvent({ action: "directory.scim_token_created", stream: orgStream(spaceId), actorId, subjectId: null, data: { organizationId: spaceId, tokenId: String(created._id), name: label } });
  return { ...view(created.toObject() as TokenDoc), token };
}

export async function revokeScimToken(actorId: string, spaceId: string, tokenId: string) {
  await requireDomainOwner(spaceId, actorId);
  if (!Types.ObjectId.isValid(tokenId)) throw new AppError("Token not found", 404, "not_found");
  const r = await ScimToken.updateOne({ _id: new Types.ObjectId(tokenId), organizationId: new Types.ObjectId(spaceId), revokedAt: null }, { $set: { revokedAt: new Date() } });
  if (!r.modifiedCount) throw new AppError("Token not found", 404, "not_found");
  await recordEvent({ action: "directory.scim_token_revoked", stream: orgStream(spaceId), actorId, subjectId: null, data: { organizationId: spaceId, tokenId } });
}

/** Groups whose members are the space's admins (directory group sync to roles). */
export async function setScimAdminGroups(actorId: string, spaceId: string, groups: string[]) {
  await requireDomainOwner(spaceId, actorId);
  const clean = [...new Set(groups.map((g) => g.trim()).filter(Boolean))].slice(0, 20);
  await Organization.updateOne({ _id: new Types.ObjectId(spaceId) }, { $set: { scimAdminGroups: clean } });
  const { syncRoles } = await import("@/lib/scim/groups");
  await syncRoles(spaceId, null);
  return clean;
}

/** The space a SCIM request acts for, from its bearer token. */
export async function authenticateScim(authorization: string | null): Promise<{ organizationId: string; tokenId: string }> {
  const token = authorization?.match(/^Bearer\s+(\S+)$/i)?.[1];
  if (!token?.startsWith(PREFIX)) throw new AppError("A SCIM token is required", 401, "unauthorized");
  const found = await ScimToken.findOne({ tokenHash: hashToken(token), revokedAt: null }).lean<TokenDoc>();
  if (!found) throw new AppError("That SCIM token isn't valid", 401, "unauthorized");
  const org = await Organization.findOne({ _id: found.organizationId, status: "active" }).select("_id").lean();
  if (!org) throw new AppError("That SCIM token isn't valid", 401, "unauthorized");
  const limit = await consumeRateLimit(`scim:${String(found._id)}`, 600, 60);
  if (!limit.allowed) throw new AppError("Too many requests", 429, "rate_limited");
  if (!found.lastUsedAt || Date.now() - found.lastUsedAt.getTime() > 60_000) await ScimToken.updateOne({ _id: found._id }, { $set: { lastUsedAt: new Date() } });
  return { organizationId: String(found.organizationId), tokenId: String(found._id) };
}
