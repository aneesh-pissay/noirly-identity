import { isBlockedUser } from "@/lib/auth/user-policy";
import { OAuthError } from "@/lib/api/errors";
import { createIdToken } from "@/lib/oidc/id-token";
import { getActiveClient } from "@/lib/oauth/clients";
import { verifyPkceS256 } from "@/lib/oauth/pkce";
import { verifyPassword } from "@/lib/security/password";
import { hashToken } from "@/lib/security/crypto";
import {
  issueAccessToken,
  issueRefreshToken,
  rotateRefreshToken,
} from "@/lib/tokens/token-service";
import type { Types } from "mongoose";
import { resolveResources, scopesFor, splitScopes } from "@/lib/oauth/resources";
import { assertMayUseApp } from "@/lib/oauth/access-policy";
import { orgClaims } from "@/lib/oauth/org-context";
import { permissionsClaim } from "@/lib/authz/delivery";
import { assertOrgAllowsApp } from "@/lib/spaces/org-apps";
import { ApiResource } from "@/models/ApiResource";
import { AccessToken } from "@/models/AccessToken";
import { AuthorizationCode } from "@/models/AuthorizationCode";
import { RefreshToken } from "@/models/RefreshToken";
import { User } from "@/models/User";
import { Session } from "@/models/Session";
import { OAuthClient, type OAuthClientDocument } from "@/models/OAuthClient";

function parseBasicAuth(header: string | null): {
  clientId?: string;
  clientSecret?: string;
} {
  if (!header?.startsWith("Basic ")) {
    return {};
  }
  try {
    const decoded = Buffer.from(header.slice(6), "base64").toString("utf8");
    const idx = decoded.indexOf(":");
    if (idx < 0) return {};
    return {
      clientId: decoded.slice(0, idx),
      clientSecret: decoded.slice(idx + 1),
    };
  } catch {
    return {};
  }
}

/**
 * During a rotation's overlap the old secret still works; each use is noted
 * (at most every few minutes) so an admin can see when the app has switched.
 */
async function matchesPreviousSecret(client: OAuthClientDocument, secret: string) {
  if (!client.previousSecretHash || !client.previousSecretExpiresAt || client.previousSecretExpiresAt <= new Date()) return false;
  if (!(await verifyPassword(client.previousSecretHash, secret))) return false;
  const quiet = new Date(Date.now() - 5 * 60_000);
  await OAuthClient.updateOne(
    { _id: client._id, $or: [{ previousSecretLastUsedAt: null }, { previousSecretLastUsedAt: { $lt: quiet } }] },
    { $set: { previousSecretLastUsedAt: new Date() } },
  );
  return true;
}

export async function authenticateClient(input: {
  clientId?: string;
  clientSecret?: string;
  authorizationHeader: string | null;
}): Promise<OAuthClientDocument> {
  const basic = parseBasicAuth(input.authorizationHeader);
  const clientId = input.clientId || basic.clientId;
  const clientSecret = input.clientSecret || basic.clientSecret;

  if (!clientId) {
    throw new OAuthError("invalid_client", "client_id is required", 401);
  }

  const client = await getActiveClient(clientId);

  if (client.clientType === "confidential") {
    if (!clientSecret || !client.clientSecretHash) {
      throw new OAuthError("invalid_client", "Client authentication failed", 401);
    }
    const ok = await verifyPassword(client.clientSecretHash, clientSecret);
    if (!ok && !(await matchesPreviousSecret(client, clientSecret))) {
      throw new OAuthError("invalid_client", "Client authentication failed", 401);
    }
  }

  return client;
}

/**
 * A code presented twice may have leaked, so the tokens it already produced
 * (same client, same session, since the code was issued) are revoked
 * (RFC 6749 §4.1.2).
 */
async function revokeTokensFromCode(record: {
  clientId: string;
  sessionId: Types.ObjectId;
  createdAt?: Date;
}) {
  const filter = {
    clientId: record.clientId,
    sessionId: record.sessionId,
    revokedAt: null,
    ...(record.createdAt ? { createdAt: { $gte: record.createdAt } } : {}),
  };
  await Promise.all([
    AccessToken.updateMany(filter, { $set: { revokedAt: new Date() } }),
    RefreshToken.updateMany(filter, { $set: { revokedAt: new Date() } }),
  ]);
}

/** For a JWT access token scoped to an organization: its permissions, when the grant has the scope. */
async function withPermissions(organization: { org_id: string; org_slug: string; org_role: string }, grantScope: string, userId: unknown, sessionId: unknown): Promise<Record<string, unknown>> {
  if (!grantScope.split(/\s+/).includes("permissions")) return organization;
  return { ...organization, permissions: await permissionsClaim(organization.org_id, String(userId), sessionId) };
}

/**
 * What the access token is for. Without `resource`, an opaque token for
 * Identity's own endpoints, carrying the OpenID Connect scopes. With one of
 * the grant's resources (RFC 8707), a JWT for that API carrying only its
 * scopes. Checked before anything is spent, so a bad `resource` costs nothing.
 */
async function planAccessToken(clientId: string, grantScope: string, granted: string[], requested: string | undefined) {
  const scopes = grantScope.split(/\s+/).filter(Boolean);
  if (!requested) {
    const grantedApis = granted.length ? await ApiResource.find({ identifier: { $in: granted } }).select("scopes").lean() : [];
    return { scope: splitScopes(scopes, grantedApis).oidc.join(" "), resource: null };
  }
  if (requested.includes(" ") || !granted.includes(requested)) {
    throw new OAuthError("invalid_target", "resource must be one this grant was given for");
  }
  const [resource] = await resolveResources(clientId, [requested]);
  return { scope: scopesFor(resource!, scopes).join(" "), resource: resource! };
}

export async function exchangeAuthorizationCode(input: {
  code: string;
  redirectUri: string;
  clientId?: string;
  clientSecret?: string;
  codeVerifier?: string;
  authorizationHeader: string | null;
  resource?: string;
}) {
  const client = await authenticateClient(input);

  const record = await AuthorizationCode.findOne({
    codeHash: hashToken(input.code),
  });

  if (!record) {
    throw new OAuthError("invalid_grant", "Invalid authorization code");
  }

  if (record.usedAt) {
    await revokeTokensFromCode(record);
    throw new OAuthError("invalid_grant", "Authorization code already used");
  }

  if (record.expiresAt.getTime() <= Date.now()) {
    throw new OAuthError("invalid_grant", "Authorization code expired");
  }

  if (record.clientId !== client.clientId) {
    throw new OAuthError("invalid_grant", "Authorization code client mismatch");
  }

  if (record.redirectUri !== input.redirectUri) {
    throw new OAuthError("invalid_grant", "redirect_uri mismatch");
  }

  if (record.codeChallenge) {
    if (!input.codeVerifier) {
      throw new OAuthError("invalid_grant", "code_verifier is required");
    }
    if (record.codeChallengeMethod !== "S256") {
      throw new OAuthError("invalid_grant", "Unsupported code challenge method");
    }
    if (!verifyPkceS256(input.codeVerifier, record.codeChallenge)) {
      throw new OAuthError("invalid_grant", "PKCE verification failed");
    }
  } else if (client.clientType === "public" || client.requirePkce) {
    throw new OAuthError("invalid_grant", "PKCE verification failed");
  }

  const plan = await planAccessToken(client.clientId, record.scope, record.resources ?? [], input.resource);

  // Claim the code atomically: of two requests racing with the same code, only
  // one gets tokens. The loser is treated like any reuse below.
  const claimed = await AuthorizationCode.findOneAndUpdate(
    { _id: record._id, usedAt: null },
    { $set: { usedAt: new Date() } },
  );
  if (!claimed) {
    await revokeTokensFromCode(record);
    throw new OAuthError("invalid_grant", "Authorization code already used");
  }

  const user = await User.findById(record.userId);
  if (!user || isBlockedUser(user) || !user.emailVerified) {
    throw new OAuthError("invalid_grant", "User is not available");
  }
  await assertMayUseApp(client, user._id);
  // Scoped to an organization: still a member? (lib/oauth/org-context.ts)
  const organization = record.organizationId ? await orgClaims(record.organizationId, user._id) : null;
  if (record.organizationId) await assertOrgAllowsApp(record.organizationId, user._id, client);

  const session = await Session.findById(record.sessionId);
  if (!session || session.revokedAt || session.expiresAt.getTime() <= Date.now()) {
    throw new OAuthError("invalid_grant", "Session is no longer valid");
  }

  const access = await issueAccessToken({
    clientId: client.clientId,
    userId: user._id,
    sessionId: session._id,
    scope: plan.scope,
    ...(plan.resource ? { resource: { identifier: plan.resource.identifier, ttlSeconds: plan.resource.accessTokenTtlSeconds, authTime: record.authTime, methods: record.methods ?? [] } } : {}),
    organization: organization ? { id: organization.org_id, claims: await withPermissions(organization, record.scope, user._id, session._id) } : null,
  });

  const scopes = new Set(record.scope.split(/\s+/));
  let refreshToken: string | undefined;
  if (scopes.has("offline_access")) {
    const refresh = await issueRefreshToken({
      clientId: client.clientId,
      userId: user._id,
      sessionId: session._id,
      scope: record.scope,
      resources: record.resources ?? [],
      organizationId: record.organizationId ?? null,
    });
    refreshToken = refresh.token;
  }

  const idToken = await createIdToken({
    user,
    clientId: client.clientId,
    scope: record.scope,
    nonce: record.nonce,
    authTime: record.authTime,
    methods: record.methods ?? [],
    sessionId: session._id,
    organization,
  });

  return {
    access_token: access.token,
    token_type: "Bearer",
    expires_in: access.expiresIn,
    refresh_token: refreshToken,
    id_token: idToken,
    // What this access token carries (RFC 6749 §5.1).
    scope: plan.scope,
  };
}

export async function exchangeRefreshToken(input: {
  refreshToken: string;
  clientId?: string;
  clientSecret?: string;
  scope?: string;
  authorizationHeader: string | null;
  resource?: string;
}) {
  const client = await authenticateClient(input);
  // A bad `resource` is refused before the refresh token is spent.
  const existing = await RefreshToken.findOne({ tokenHash: hashToken(input.refreshToken), clientId: client.clientId }).select("resources scope").lean();
  if (input.resource) await planAccessToken(client.clientId, existing?.scope ?? "", existing?.resources ?? [], input.resource);
  const rotated = await rotateRefreshToken(input.refreshToken, client.clientId);

  if (rotated.error === "reuse_detected") {
    throw new OAuthError(
      "invalid_grant",
      "Refresh token reuse detected; token family revoked",
    );
  }

  if (rotated.error || !rotated.previous) {
    throw new OAuthError("invalid_grant", "Invalid refresh token");
  }

  const previous = rotated.previous;
  let scope = previous.scope;
  if (input.scope) {
    const requested = input.scope.split(/\s+/).filter(Boolean);
    const granted = new Set(previous.scope.split(/\s+/));
    if (requested.some((s) => !granted.has(s))) {
      throw new OAuthError("invalid_scope", "Cannot expand scopes on refresh");
    }
    scope = requested.join(" ");
  }

  const user = await User.findById(previous.userId);
  if (!user || isBlockedUser(user) || !user.emailVerified) {
    throw new OAuthError("invalid_grant", "User is not available");
  }
  // Taken out of the app's spaces or allowlist since: the grant ends here.
  await assertMayUseApp(client, user._id);
  // Scoped to an organization: still a member?
  const organization = previous.organizationId ? await orgClaims(previous.organizationId, user._id) : null;
  if (previous.organizationId) await assertOrgAllowsApp(previous.organizationId, user._id, client);

  const session = await Session.findById(previous.sessionId);
  if (!session || session.revokedAt || session.expiresAt.getTime() <= Date.now()) {
    throw new OAuthError("invalid_grant", "Session is no longer valid");
  }

  const plan = await planAccessToken(client.clientId, scope, previous.resources ?? [], input.resource);
  const access = await issueAccessToken({
    clientId: client.clientId,
    userId: user._id,
    sessionId: session._id,
    scope: plan.scope,
    ...(plan.resource ? { resource: { identifier: plan.resource.identifier, ttlSeconds: plan.resource.accessTokenTtlSeconds, authTime: session.authenticatedAt ?? session.createdAt, methods: session.methods ?? [] } } : {}),
    organization: organization ? { id: organization.org_id, claims: await withPermissions(organization, scope, user._id, session._id) } : null,
  });

  const idToken = await createIdToken({
    user,
    clientId: client.clientId,
    scope,
    // The sign-in behind this refresh, not the refresh itself.
    authTime: session.authenticatedAt ?? session.createdAt,
    methods: session.methods ?? [],
    sessionId: session._id,
    organization,
  });

  return {
    access_token: access.token,
    token_type: "Bearer",
    expires_in: access.expiresIn,
    refresh_token: rotated.refreshToken,
    id_token: idToken,
    scope: plan.scope,
  };
}
