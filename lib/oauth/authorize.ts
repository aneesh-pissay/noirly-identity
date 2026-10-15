import { OAuthError } from "@/lib/api/errors";
import { requireAuthContext } from "@/lib/auth/auth-service";
import { assertEmailVerified } from "@/lib/auth/user-policy";
import { getEnv } from "@/lib/config/env";
import {
  assertExactRedirectUri,
  getActiveClient,
} from "@/lib/oauth/clients";
import { requirePkceForClient } from "@/lib/oauth/pkce";
import { generateSecureToken, hashToken } from "@/lib/security/crypto";
import {
  parseScopes,
  validateRequestedScopes,
} from "@/lib/validation/schemas";
import { AuthorizationCode } from "@/models/AuthorizationCode";

export type AuthorizeParams = {
  client_id: string;
  redirect_uri: string;
  response_type: "code";
  scope: string;
  state: string;
  code_challenge?: string;
  code_challenge_method?: "S256";
  nonce?: string;
  prompt?: "none" | "login" | "consent" | "select_account";
};

export async function validateAuthorizeRequest(params: AuthorizeParams) {
  const client = await getActiveClient(params.client_id);
  assertExactRedirectUri(client, params.redirect_uri);

  requirePkceForClient({
    clientType: client.clientType,
    requirePkce: client.requirePkce,
    codeChallenge: params.code_challenge,
    codeChallengeMethod: params.code_challenge_method,
  });

  const requested = parseScopes(params.scope);
  const scopeCheck = validateRequestedScopes(requested, client.allowedScopes);
  if (!scopeCheck.ok) {
    throw new OAuthError("invalid_scope", scopeCheck.message);
  }

  return {
    client,
    scopes: scopeCheck.scopes,
    scopeString: scopeCheck.scopes.join(" "),
  };
}

export async function createAuthorizationCode(input: {
  sessionToken: string | null;
  clientId: string;
  redirectUri: string;
  scope: string;
  codeChallenge?: string | null;
  codeChallengeMethod?: "S256" | null;
  nonce?: string | null;
}): Promise<{ code: string }> {
  const auth = await requireAuthContext(input.sessionToken);
  assertEmailVerified(auth.user);
  const env = getEnv();
  const code = generateSecureToken(32);

  await AuthorizationCode.create({
    codeHash: hashToken(code),
    clientId: input.clientId,
    userId: auth.user._id,
    sessionId: auth.session._id,
    redirectUri: input.redirectUri,
    scope: input.scope,
    codeChallenge: input.codeChallenge ?? null,
    codeChallengeMethod: input.codeChallengeMethod ?? null,
    nonce: input.nonce ?? null,
    authTime: auth.user.lastLoginAt ?? auth.session.createdAt,
    expiresAt: new Date(Date.now() + env.AUTH_CODE_TTL_SECONDS * 1000),
  });

  return { code };
}
