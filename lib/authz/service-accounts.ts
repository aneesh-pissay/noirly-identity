import { randomBytes } from "node:crypto";
import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { orgStream } from "@/lib/audit/chain";
import { recordEvent, type RequestMeta } from "@/lib/audit/event-log";
import { requireAccessAdmin } from "@/lib/authz/admin";
import { updateAppClient } from "@/lib/oauth/client-admin";
import { generateSecureToken } from "@/lib/security/crypto";
import { hashPassword } from "@/lib/security/password";
import { AccessToken } from "@/models/AccessToken";
import { RoleAssignment, ServiceAccount } from "@/models/Authz";
import { OAuthClient } from "@/models/OAuthClient";
import { Organization } from "@/models/Organization";

/**
 * Service accounts: an organization's own non-human accounts (a nightly job,
 * an integration). Each is a confidential client with its own secret that
 * can only act as itself (client credentials) and can never sign people in.
 * It has exactly the privileges its organization delegates to it through
 * roles (lib/authz/admin.ts), in that organization only, and they can be
 * narrowed to resources and conditions like anyone's. Tokens last 15 minutes;
 * disabling it stops them at once. Managed by admins with the access area.
 */

export type ServiceAccountView = { id: string; name: string; clientId: string; disabled: boolean; createdAt: string };

const view = (a: { _id: Types.ObjectId; name: string; clientId: string; disabledAt?: Date | null; createdAt: Date }): ServiceAccountView => ({
  id: String(a._id),
  name: a.name,
  clientId: a.clientId,
  disabled: Boolean(a.disabledAt),
  createdAt: a.createdAt.toISOString(),
});

const oid = (id: string, what = "Service account") => {
  if (!Types.ObjectId.isValid(id)) throw new AppError(`${what} not found`, 404, "not_found");
  return new Types.ObjectId(id);
};

export async function listServiceAccounts(actorId: string, spaceId: string) {
  await requireAccessAdmin(spaceId, actorId);
  return (await ServiceAccount.find({ organizationId: oid(spaceId, "Space") }).sort({ name: 1 }).lean()).map(view);
}

/** Creates one; its secret is returned once. */
export async function createServiceAccount(actorId: string, spaceId: string, nameInput: string, meta: RequestMeta = {}) {
  await requireAccessAdmin(spaceId, actorId);
  const name = nameInput.trim();
  if (!name || name.length > 60) throw new AppError("Give it a name (up to 60 characters)", 400, "invalid_request");
  const org = await Organization.findById(oid(spaceId, "Space")).select("slug").lean();
  if (!org) throw new AppError("Space not found", 404, "not_found");
  if (await ServiceAccount.exists({ organizationId: org._id, name })) throw new AppError("There's already a service account with that name", 409, "duplicate");
  const clientId = `sa-${org.slug.slice(0, 30)}-${randomBytes(4).toString("hex")}`;
  const clientSecret = generateSecureToken(32);
  await OAuthClient.create({
    clientId,
    clientSecretHash: await hashPassword(clientSecret),
    name: `${name} (service account)`,
    description: `Service account of ${org.slug}`,
    // Never used: service accounts don't sign people in (the field can't be empty).
    redirectUris: ["urn:noirly:service-account"],
    allowedScopes: [],
    clientType: "confidential",
    status: "active",
    requireConsent: false,
    serviceAccountOf: org._id,
  });
  const account = await ServiceAccount.create({ organizationId: org._id, name, clientId, createdBy: oid(actorId, "User") });
  await recordEvent({ action: "authz.service_account_created", stream: orgStream(spaceId), actorId, subjectId: null, request: meta, data: { serviceAccountId: String(account._id), name, clientId, organizationId: spaceId } });
  return { serviceAccount: view(account.toObject()), clientSecret };
}

/** A new secret; the old one stops at once. */
export async function rotateServiceAccountSecret(actorId: string, spaceId: string, accountId: string) {
  await requireAccessAdmin(spaceId, actorId);
  const account = await ServiceAccount.findOne({ _id: oid(accountId), organizationId: oid(spaceId, "Space"), disabledAt: null }).lean();
  if (!account) throw new AppError("Service account not found", 404, "not_found");
  const { clientSecret } = await updateAppClient(account.clientId, { rotateSecret: true, secretOverlapSeconds: 0, revokeMachineTokens: true });
  return { serviceAccount: view(account), clientSecret: clientSecret! };
}

/** Disables it: its client stops, its tokens stop, and its roles go. */
export async function disableServiceAccount(actorId: string, spaceId: string, accountId: string, meta: RequestMeta = {}) {
  await requireAccessAdmin(spaceId, actorId);
  const account = await ServiceAccount.findOneAndUpdate({ _id: oid(accountId), organizationId: oid(spaceId, "Space"), disabledAt: null }, { $set: { disabledAt: new Date() } }, { returnDocument: "after" }).lean();
  if (!account) throw new AppError("Service account not found", 404, "not_found");
  await Promise.all([
    OAuthClient.updateOne({ clientId: account.clientId }, { $set: { status: "disabled" } }),
    AccessToken.updateMany({ clientId: account.clientId, revokedAt: null }, { $set: { revokedAt: new Date() } }),
    RoleAssignment.deleteMany({ subjectType: "service", subjectId: account._id }),
  ]);
  await recordEvent({ action: "authz.service_account_disabled", stream: orgStream(spaceId), actorId, subjectId: null, request: meta, data: { serviceAccountId: accountId, name: account.name, organizationId: spaceId } });
  return view(account);
}
