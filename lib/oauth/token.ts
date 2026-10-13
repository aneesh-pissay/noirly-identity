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
import { AuthorizationCode } from "@/models/AuthorizationCode";
import { User } from "@/models/User";
import { Session } from "@/models/Session";
import type { OAuthClientDocument } from "@/models/OAuthClient";

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

async function authenticateClient(input: {
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
    if (!ok) {
      throw new OAuthError("invalid_client", "Client authentication failed", 401);
    }
  }

  return client;
}

export async function exchangeAuthorizationCode(input: {
  code: string;
  redirectUri: string;
  clientId?: string;
  clientSecret?: string;
  codeVerifier?: string;
  authorizationHeader: string | null;
}) {
  const client = await authenticateClient(input);

  const record = await AuthorizationCode.findOne({
    codeHash: hashToken(input.code),
  });

  if (!record) {
    throw new OAuthError("invalid_grant", "Invalid authorization code");
  }

  if (record.usedAt) {
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

  record.usedAt = new Date();
  await record.save();

  const user = await User.findById(record.userId);
  if (!user || isBlockedUser(user)) {
    throw new OAuthError("invalid_grant", "User is not available");
  }

  const session = await Session.findById(record.sessionId);
  if (!session || session.revokedAt || session.expiresAt.getTime() <= Date.now()) {
    throw new OAuthError("invalid_grant", "Session is no longer valid");
  }

  const access = await issueAccessToken({
    clientId: client.clientId,
    userId: user._id,
    sessionId: session._id,
    scope: record.scope,
  });

  const scopes = new Set(record.scope.split(/\s+/));
  let refreshToken: string | undefined;
  if (scopes.has("offline_access")) {
    const refresh = await issueRefreshToken({
      clientId: client.clientId,
      userId: user._id,
      sessionId: session._id,
      scope: record.scope,
    });
    refreshToken = refresh.token;
  }

  const idToken = await createIdToken({
    user,
    clientId: client.clientId,
    scope: record.scope,
    nonce: record.nonce,
    authTime: record.authTime,
  });

  return {
    access_token: access.token,
    token_type: "Bearer",
    expires_in: access.expiresIn,
    refresh_token: refreshToken,
    id_token: idToken,
    scope: record.scope,
  };
}

export async function exchangeRefreshToken(input: {
  refreshToken: string;
  clientId?: string;
  clientSecret?: string;
  scope?: string;
  authorizationHeader: string | null;
}) {
  const client = await authenticateClient(input);
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
  if (!user || isBlockedUser(user)) {
    throw new OAuthError("invalid_grant", "User is not available");
  }

  const session = await Session.findById(previous.sessionId);
  if (!session || session.revokedAt || session.expiresAt.getTime() <= Date.now()) {
    throw new OAuthError("invalid_grant", "Session is no longer valid");
  }

  const access = await issueAccessToken({
    clientId: client.clientId,
    userId: user._id,
    sessionId: session._id,
    scope,
  });

  const idToken = await createIdToken({
    user,
    clientId: client.clientId,
    scope,
    authTime: user.lastLoginAt ?? session.createdAt,
  });

  return {
    access_token: access.token,
    token_type: "Bearer",
    expires_in: access.expiresIn,
    refresh_token: rotated.refreshToken,
    id_token: idToken,
    scope,
  };
}
