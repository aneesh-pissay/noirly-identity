import { isBlockedUser } from "@/lib/auth/user-policy";
import { AppError } from "@/lib/api/errors";
import { getEnv } from "@/lib/config/env";
import { getActiveClient } from "@/lib/oauth/clients";
import { createIdToken } from "@/lib/oidc/id-token";
import {
  refreshSessionExpiry,
  validateSession,
} from "@/lib/sessions/session-service";
import {
  issueAccessToken,
  issueRefreshToken,
} from "@/lib/tokens/token-service";
import {
  parseScopes,
  validateRequestedScopes,
} from "@/lib/validation/schemas";
import { User } from "@/models/User";
import type { OAuthClientDocument } from "@/models/OAuthClient";
import type { PublicUser } from "@/types";

export type MobileTokenResponse = {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token?: string;
  id_token: string;
  scope: string;
  user: PublicUser;
};

export const DEFAULT_MOBILE_SCOPES =
  "openid profile email offline_access";

export async function requirePublicMobileClient(
  clientId: string,
): Promise<OAuthClientDocument> {
  const client = await getActiveClient(clientId);
  if (client.clientType !== "public") {
    throw new AppError(
      "Mobile auth requires a public OAuth client",
      400,
      "invalid_client",
    );
  }
  return client;
}

export function resolveMobileScope(
  client: OAuthClientDocument,
  requestedScope?: string | null,
): string {
  const requested = parseScopes(requestedScope?.trim() || DEFAULT_MOBILE_SCOPES);
  const validated = validateRequestedScopes(requested, client.allowedScopes);
  if (!validated.ok) {
    throw new AppError(validated.message, 400, "invalid_scope");
  }
  return validated.scopes.join(" ");
}

export async function mintMobileTokens(input: {
  clientId: string;
  sessionToken: string;
  scope: string;
  user: PublicUser;
  nonce?: string | null;
}): Promise<MobileTokenResponse> {
  const sessionCtx = await validateSession(input.sessionToken);
  if (!sessionCtx) {
    throw new AppError("Session is no longer valid", 401, "invalid_session");
  }

  const user = await User.findById(sessionCtx.userId);
  if (!user || isBlockedUser(user)) {
    throw new AppError("User is not available", 401, "invalid_credentials");
  }

  const env = getEnv();
  await refreshSessionExpiry(sessionCtx.session._id, env.REFRESH_TOKEN_TTL_SECONDS);

  const access = await issueAccessToken({
    clientId: input.clientId,
    userId: user._id,
    sessionId: sessionCtx.session._id,
    scope: input.scope,
  });

  const scopes = new Set(input.scope.split(/\s+/));
  let refreshToken: string | undefined;
  if (scopes.has("offline_access")) {
    const refresh = await issueRefreshToken({
      clientId: input.clientId,
      userId: user._id,
      sessionId: sessionCtx.session._id,
      scope: input.scope,
    });
    refreshToken = refresh.token;
  }

  const idToken = await createIdToken({
    user,
    clientId: input.clientId,
    scope: input.scope,
    nonce: input.nonce,
    authTime: user.lastLoginAt ?? sessionCtx.session.createdAt,
  });

  return {
    access_token: access.token,
    token_type: "Bearer",
    expires_in: access.expiresIn,
    refresh_token: refreshToken,
    id_token: idToken,
    scope: input.scope,
    user: input.user,
  };
}
