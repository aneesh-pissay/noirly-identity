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
import { refreshSessionExpiry, revokeSession } from "@/lib/sessions/session-service";
import { loginWithAppleProfile, verifyAppleIdToken } from "@/lib/auth/apple";
import type {
  loginSchema,
  mobileAppleSchema,
  mobileGoogleSchema,
  mobileRefreshSchema,
  registerSchema,
} from "@/lib/validation/schemas";
import { RefreshToken } from "@/models/RefreshToken";
import { User } from "@/models/User";
import { recordEvent } from "@/lib/audit/event-log";
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
  if (!result.user.emailVerified) {
    // The account exists and the email is on its way; tokens come at sign-in
    // once the address is proven. The SDK shows this message.
    throw new AppError(
      "Account created. Check your email to verify your address, then sign in.",
      403,
      "email_not_verified",
    );
  }
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

export async function mobileLoginWithApple(
  input: z.infer<typeof mobileAppleSchema>,
  meta: Meta,
): Promise<MobileTokenResponse> {
  const client = await requirePublicMobileClient(input.client_id);
  const scope = resolveMobileScope(client, input.scope);
  const profile = await verifyAppleIdToken({
    idToken: input.id_token,
    nonce: input.apple_nonce,
    native: true,
    name: { firstName: input.first_name, lastName: input.last_name },
  });
  const result = await loginWithAppleProfile(profile, { ...meta, mobileMfa: { clientId: client.clientId, scope, nonce: input.nonce } });
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

  // Ends the session and its tokens, and tells the other apps it reached.
  await revokeSession(existing.sessionId);
  await recordEvent({ action: "auth.signed_out", subjectId: existing.userId, clientId: input.client_id });
}
