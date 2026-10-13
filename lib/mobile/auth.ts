import { isBlockedUser } from "@/lib/auth/user-policy";
import { AppError } from "@/lib/api/errors";
import { loginUser, registerUser } from "@/lib/auth/auth-service";
import {
  loginWithGoogleProfile,
  verifyGoogleIdToken,
} from "@/lib/auth/google";
import { toPublicUser } from "@/lib/auth/user-mapper";
import { getEnv } from "@/lib/config/env";
import {
  mintMobileTokens,
  requirePublicMobileClient,
  resolveMobileScope,
  type MobileTokenResponse,
} from "@/lib/mobile/mint-tokens";
import { exchangeRefreshToken } from "@/lib/oauth/token";
import { hashToken } from "@/lib/security/crypto";
import { refreshSessionExpiry } from "@/lib/sessions/session-service";
import {
  revokeAccessTokensForSession,
  revokeRefreshTokensForSession,
} from "@/lib/tokens/token-service";
import type {
  loginSchema,
  mobileGoogleSchema,
  mobileRefreshSchema,
  registerSchema,
} from "@/lib/validation/schemas";
import { RefreshToken } from "@/models/RefreshToken";
import { Session } from "@/models/Session";
import { User } from "@/models/User";
import type { z } from "zod";

type Meta = { ipAddress?: string | null; userAgent?: string | null };

export async function mobileLoginWithPassword(
  input: z.infer<typeof loginSchema> & {
    client_id: string;
    scope?: string;
    nonce?: string;
  },
  meta: Meta,
): Promise<MobileTokenResponse> {
  const client = await requirePublicMobileClient(input.client_id);
  const scope = resolveMobileScope(client, input.scope);
  const result = await loginUser(
    { email: input.email, password: input.password },
    { ...meta, mobileMfa: { clientId: client.clientId, scope, nonce: input.nonce } },
  );
  return mintMobileTokens({
    clientId: client.clientId,
    sessionToken: result.sessionToken,
    scope,
    user: result.user,
    nonce: input.nonce,
  });
}

export async function mobileRegister(
  input: z.infer<typeof registerSchema> & {
    client_id: string;
    scope?: string;
    nonce?: string;
  },
  meta: Meta,
): Promise<MobileTokenResponse> {
  const client = await requirePublicMobileClient(input.client_id);
  const scope = resolveMobileScope(client, input.scope);
  const result = await registerUser(
    {
      email: input.email,
      password: input.password,
      firstName: input.firstName,
      lastName: input.lastName,
      displayName: input.displayName,
      phoneNumber: input.phoneNumber,
    },
    meta,
  );
  return mintMobileTokens({
    clientId: client.clientId,
    sessionToken: result.sessionToken,
    scope,
    user: result.user,
    nonce: input.nonce,
  });
}

export async function mobileLoginWithGoogle(
  input: z.infer<typeof mobileGoogleSchema>,
  meta: Meta,
): Promise<MobileTokenResponse> {
  const client = await requirePublicMobileClient(input.client_id);
  const scope = resolveMobileScope(client, input.scope);
  const profile = await verifyGoogleIdToken({
    credential: input.id_token,
    nonce: input.nonce,
  });
  const result = await loginWithGoogleProfile(profile, { ...meta, mobileMfa: { clientId: client.clientId, scope, nonce: input.nonce } });
  return mintMobileTokens({
    clientId: client.clientId,
    sessionToken: result.sessionToken,
    scope,
    user: result.user,
    nonce: input.nonce,
  });
}

export async function mobileRefreshTokens(
  input: z.infer<typeof mobileRefreshSchema>,
): Promise<MobileTokenResponse> {
  await requirePublicMobileClient(input.client_id);

  const tokens = await exchangeRefreshToken({
    refreshToken: input.refresh_token,
    clientId: input.client_id,
    authorizationHeader: null,
    scope: input.scope,
  });

  if (!tokens.refresh_token) {
    throw new AppError("Refresh token missing from response", 500, "internal_error");
  }

  const refreshRecord = await RefreshToken.findOne({
    tokenHash: hashToken(tokens.refresh_token),
  });
  if (!refreshRecord) {
    throw new AppError("User is not available", 401, "invalid_credentials");
  }

  const env = getEnv();
  await refreshSessionExpiry(refreshRecord.sessionId, env.REFRESH_TOKEN_TTL_SECONDS);

  const user = await User.findById(refreshRecord.userId);
  if (!user || isBlockedUser(user)) {
    throw new AppError("User is not available", 401, "invalid_credentials");
  }

  return {
    access_token: tokens.access_token,
    token_type: "Bearer",
    expires_in: tokens.expires_in,
    refresh_token: tokens.refresh_token,
    id_token: tokens.id_token,
    scope: tokens.scope,
    user: toPublicUser(user),
  };
}

export async function mobileLogout(input: {
  client_id: string;
  refresh_token?: string | null;
}): Promise<void> {
  await requirePublicMobileClient(input.client_id);

  if (!input.refresh_token) {
    return;
  }

  const existing = await RefreshToken.findOne({
    tokenHash: hashToken(input.refresh_token),
  });
  if (!existing || existing.clientId !== input.client_id) {
    return;
  }

  await revokeRefreshTokensForSession(existing.sessionId);
  await revokeAccessTokensForSession(existing.sessionId);
  await Session.findByIdAndUpdate(existing.sessionId, {
    revokedAt: new Date(),
  });
}
