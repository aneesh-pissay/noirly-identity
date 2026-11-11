import { randomUUID } from "node:crypto";
import { SignJWT } from "jose";
import { OAuthError } from "@/lib/api/errors";
import { getEnv } from "@/lib/config/env";
import { getSigningKeys } from "@/lib/oidc/keys";
import { hashToken } from "@/lib/security/crypto";
import { AccessToken } from "@/models/AccessToken";
import { ApiResource, type ApiResourceDocument } from "@/models/ApiResource";
import { OAuthClient, type OAuthClientDocument } from "@/models/OAuthClient";

/**
 * The client credentials grant (RFC 6749 §4.4): a confidential app gets a
 * token as itself, for a service-to-service call with no person behind it.
 *
 * Machine access is granted per API: a registered API lists which apps may
 * call it alone (`machineGrants`) and with which of its scopes. The token is
 * always for exactly one API (`resource` is required), as a JWT (RFC 9068)
 * whose `sub` and `client_id` are the app. There's no refresh token and no ID
 * token; the app asks again when it runs out.
 */

export type MachineGrant = { clientId: string; scopes: string[] };

export function machineGrantFor(resource: Pick<ApiResourceDocument, "machineGrants">, clientId: string): MachineGrant | null {
  return resource.machineGrants?.find((g) => g.clientId === clientId) ?? null;
}

export async function issueClientCredentialsToken(input: { client: OAuthClientDocument; resource?: string; scope?: string }) {
  if (input.client.clientType !== "confidential") {
    throw new OAuthError("unauthorized_client", "Only confidential clients can act as themselves");
  }
  // A service account without a resource gets a token for Identity's permissions API.
  if (!input.resource && input.client.serviceAccountOf) return issueServiceAccountToken(input.client);
  if (!input.resource) throw new OAuthError("invalid_target", "resource is required: a machine token is for one API");
  const resource = await ApiResource.findOne({ identifier: input.resource, status: "active" }).lean<ApiResourceDocument>();
  const grant = resource ? machineGrantFor(resource, input.client.clientId) : null;
  if (!resource || !grant) throw new OAuthError("invalid_target", "This app may not call that API as itself");

  // Asked-for scopes must be granted; none asked for means everything granted.
  const defined = new Set(resource.scopes.map((s) => s.name));
  const allowed = grant.scopes.filter((s) => defined.has(s));
  const requested = (input.scope ?? "").split(/\s+/).filter(Boolean);
  const outside = requested.filter((s) => !allowed.includes(s));
  if (outside.length) throw new OAuthError("invalid_scope", `Not granted to this app: ${outside.join(" ")}`);
  const scope = (requested.length ? requested : allowed).join(" ");

  const keys = await getSigningKeys();
  const now = Math.floor(Date.now() / 1000);
  const expiresIn = resource.accessTokenTtlSeconds;
  const token = await new SignJWT({ client_id: input.client.clientId, scope, ...(await serviceAccountClaims(input.client)) })
    .setProtectedHeader({ alg: "RS256", kid: keys.kid, typ: "at+jwt" })
    .setIssuer(getEnv().OIDC_ISSUER)
    .setSubject(input.client.clientId)
    .setAudience(resource.identifier)
    .setIssuedAt(now)
    .setExpirationTime(now + expiresIn)
    .setJti(randomUUID())
    .sign(keys.privateKey);

  // Kept (hashed) so introspection can answer for it, and it can be revoked.
  await AccessToken.create({
    tokenHash: hashToken(token),
    clientId: input.client.clientId,
    kind: "machine",
    scope,
    audience: resource.identifier,
    expiresAt: new Date((now + expiresIn) * 1000),
  });

  return { access_token: token, token_type: "Bearer", expires_in: expiresIn, scope };
}

/**
 * Is a machine token still good? Not expired or revoked, its app still active,
 * and the API still granting that app machine access.
 */
export async function machineTokenIsLive(token: { clientId: string; audience?: string | null; revokedAt?: Date | null; expiresAt: Date }) {
  if (token.revokedAt || token.expiresAt <= new Date() || !token.audience) return false;
  if (token.audience === identityAuthzAudience()) {
    return Boolean(await OAuthClient.exists({ clientId: token.clientId, status: "active", serviceAccountOf: { $ne: null } }));
  }
  const [client, resource] = await Promise.all([
    OAuthClient.exists({ clientId: token.clientId, status: "active" }),
    ApiResource.findOne({ identifier: token.audience, status: "active" }).select("machineGrants").lean<ApiResourceDocument>(),
  ]);
  return Boolean(client && resource && machineGrantFor(resource, token.clientId));
}

/** The audience of a service account's token for Identity's own permissions API (app/api/authz). */
export function identityAuthzAudience() {
  return `${getEnv().OIDC_ISSUER.replace(/\/$/, "")}/api/authz`;
}

const SERVICE_TOKEN_SECONDS = 900;

/** For a service account: its organization and what its roles let it do (lib/authz). */
async function serviceAccountClaims(client: OAuthClientDocument): Promise<Record<string, unknown>> {
  if (!client.serviceAccountOf) return {};
  const { ServiceAccount } = await import("@/models/Authz");
  const { effectivePermissions } = await import("@/lib/authz/engine");
  const account = await ServiceAccount.findOne({ clientId: client.clientId, disabledAt: null }).lean();
  if (!account) throw new OAuthError("invalid_client", "This service account is disabled", 401);
  const orgId = String(account.organizationId);
  return { org_id: orgId, service_account: String(account._id), permissions: await effectivePermissions(orgId, { type: "service", id: String(account._id) }) };
}

/** A service account's token for Identity's permissions API: no API grant needed, its roles say what it may do. */
async function issueServiceAccountToken(client: OAuthClientDocument) {
  const claims = await serviceAccountClaims(client);
  const keys = await getSigningKeys();
  const now = Math.floor(Date.now() / 1000);
  const audience = identityAuthzAudience();
  // "authz": good for Identity's permissions API only.
  const token = await new SignJWT({ client_id: client.clientId, scope: "authz", ...claims })
    .setProtectedHeader({ alg: "RS256", kid: keys.kid, typ: "at+jwt" })
    .setIssuer(getEnv().OIDC_ISSUER)
    .setSubject(client.clientId)
    .setAudience(audience)
    .setIssuedAt(now)
    .setExpirationTime(now + SERVICE_TOKEN_SECONDS)
    .setJti(randomUUID())
    .sign(keys.privateKey);
  await AccessToken.create({ tokenHash: hashToken(token), clientId: client.clientId, kind: "machine", scope: "authz", audience, expiresAt: new Date((now + SERVICE_TOKEN_SECONDS) * 1000) });
  return { access_token: token, token_type: "Bearer", expires_in: SERVICE_TOKEN_SECONDS, scope: "authz" };
}
