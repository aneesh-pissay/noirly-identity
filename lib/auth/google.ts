import { isBlockedUser } from "@/lib/auth/user-policy";
import { requireSecondFactor, type MobileMfaContext } from "@/lib/security/mfa";
import { createHash } from "node:crypto";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { AppError } from "@/lib/api/errors";
import { normalizeEmail, toPublicUser } from "@/lib/auth/user-mapper";
import { getEnv } from "@/lib/config/env";
import { generateSecureToken } from "@/lib/security/crypto";
import { createSession, revokeAllUserSessions } from "@/lib/sessions/session-service";
import { AccessToken } from "@/models/AccessToken";
import { AuthorizationCode } from "@/models/AuthorizationCode";
import { LinkedAccount } from "@/models/LinkedAccount";
import { MobileBrowserLogin } from "@/models/MobileBrowserLogin";
import { PasswordResetToken } from "@/models/PasswordResetToken";
import { RefreshToken } from "@/models/RefreshToken";
import { Mfa, Passkey, SecurityChallenge } from "@/models/SecurityCredential";
import { User, type UserDocument } from "@/models/User";
import type { PublicUser } from "@/types";

export type GoogleProfile = {
  sub: string;
  email: string;
  emailVerified: boolean;
  firstName: string;
  lastName: string;
  displayName: string;
  avatarUrl: string | null;
};

export function isGoogleOAuthConfigured(): boolean {
  const env = getEnv();
  return Boolean(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET);
}

export function googleCallbackUrl(): string {
  return `${getEnv().APP_URL.replace(/\/$/, "")}/api/auth/google/callback`;
}

export function buildGoogleAuthorizationUrl(input: {
  state: string;
  nonce: string;
  codeChallenge: string;
  loginHint?: string;
}): string {
  const env = getEnv();
  if (!env.GOOGLE_CLIENT_ID) {
    throw new AppError("Google sign-in is not configured", 501, "google_not_configured");
  }

  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", env.GOOGLE_CLIENT_ID);
  url.searchParams.set("redirect_uri", googleCallbackUrl());
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid email profile");
  url.searchParams.set("state", input.state);
  url.searchParams.set("nonce", input.nonce);
  url.searchParams.set("code_challenge", input.codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("prompt", "select_account");
  if (input.loginHint) {
    url.searchParams.set("login_hint", input.loginHint);
  }
  return url.toString();
}

export function pkceChallengeS256(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

export async function exchangeGoogleCode(input: {
  code: string;
  codeVerifier: string;
}): Promise<GoogleProfile> {
  const env = getEnv();
  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) {
    throw new AppError("Google sign-in is not configured", 501, "google_not_configured");
  }

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: input.code,
    redirect_uri: googleCallbackUrl(),
    client_id: env.GOOGLE_CLIENT_ID,
    client_secret: env.GOOGLE_CLIENT_SECRET,
    code_verifier: input.codeVerifier,
  });

  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!tokenRes.ok) {
    throw new AppError("Google sign-in failed", 401, "google_auth_failed");
  }

  const tokens = (await tokenRes.json()) as { access_token?: string };
  if (!tokens.access_token) {
    throw new AppError("Google sign-in failed", 401, "google_auth_failed");
  }

  const profileRes = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
    headers: { authorization: `Bearer ${tokens.access_token}` },
  });

  if (!profileRes.ok) {
    throw new AppError("Google sign-in failed", 401, "google_auth_failed");
  }

  const profile = (await profileRes.json()) as {
    sub?: string;
    email?: string;
    email_verified?: boolean;
    given_name?: string;
    family_name?: string;
    name?: string;
    picture?: string;
  };

  if (!profile.sub || !profile.email || profile.email_verified !== true) {
    throw new AppError("Google account email is not verified", 400, "google_email_unverified");
  }

  const email = normalizeEmail(profile.email);
  const firstName = profile.given_name?.trim() || email.split("@")[0] || "Noirly";
  const lastName = profile.family_name?.trim() || "User";
  const displayName = profile.name?.trim() || `${firstName} ${lastName}`.trim();

  return {
    sub: profile.sub,
    email,
    emailVerified: true,
    firstName,
    lastName,
    displayName,
    avatarUrl: profile.picture ?? null,
  };
}

/**
 * Clears every way into an account that came from its unverified registrant:
 * password, authenticator, passkeys, other linked logins, sessions and tokens.
 */
async function discardUnverifiedRegistration(user: Pick<UserDocument, "_id" | "passwordHash">) {
  // In memory too: the caller saves this document again below.
  user.passwordHash = null;
  await Promise.all([
    User.updateOne({ _id: user._id }, { $set: { passwordHash: null } }),
    Mfa.deleteMany({ userId: user._id }),
    Passkey.deleteMany({ userId: user._id }),
    SecurityChallenge.deleteMany({ userId: user._id }),
    LinkedAccount.deleteMany({ userId: user._id }),
    PasswordResetToken.updateMany({ userId: user._id, usedAt: null }, { $set: { usedAt: new Date() } }),
    MobileBrowserLogin.deleteMany({ userId: user._id }),
    AccessToken.updateMany({ userId: user._id, revokedAt: null }, { $set: { revokedAt: new Date() } }),
    RefreshToken.updateMany({ userId: user._id, revokedAt: null }, { $set: { revokedAt: new Date() } }),
    AuthorizationCode.deleteMany({ userId: user._id }),
    revokeAllUserSessions(user._id),
  ]);
}

export async function loginWithGoogleProfile(
  profile: GoogleProfile,
  meta: { ipAddress?: string | null; userAgent?: string | null; mobileMfa?: MobileMfaContext },
): Promise<{ user: PublicUser; sessionToken: string }> {
  const linked = await LinkedAccount.findOne({
    provider: "google",
    providerAccountId: profile.sub,
  });

  let user = linked
    ? await User.findById(linked.userId).select("+passwordHash")
    : null;

  if (!user) {
    user = await User.findOne({ email: profile.email }).select("+passwordHash");
    if (user) {
      if (isBlockedUser(user)) {
        throw new AppError("Unable to sign in", 401, "invalid_credentials");
      }
      if (!user.emailVerified) {
        // Nobody ever proved they own this address, so anyone could have
        // registered it first. Google now proves the owner: drop whatever the
        // earlier registrant set up, or they keep a way into this account.
        await discardUnverifiedRegistration(user);
      }
      await LinkedAccount.create({
        userId: user._id,
        provider: "google",
        providerAccountId: profile.sub,
      });
    }
  }

  if (!user) {
    user = await User.create({
      email: profile.email,
      passwordHash: null,
      firstName: profile.firstName,
      lastName: profile.lastName,
      displayName: profile.displayName,
      avatarUrl: profile.avatarUrl,
      emailVerified: true,
      status: "active",
      roles: ["user"],
    });
    await LinkedAccount.create({
      userId: user._id,
      provider: "google",
      providerAccountId: profile.sub,
    });
  }

  if (isBlockedUser(user)) {
    throw new AppError("Unable to sign in", 401, "invalid_credentials");
  }

  user.emailVerified = true;
  if (user.status === "pending_verification") {
    user.status = "active";
  }
  if (!user.avatarUrl && profile.avatarUrl) {
    user.avatarUrl = profile.avatarUrl;
  }
  await requireSecondFactor(user._id.toString(), meta.mobileMfa);

  user.lastLoginAt = new Date();
  await user.save();

  const { token } = await createSession({
    userId: user._id,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
  });

  return { user: toPublicUser(user), sessionToken: token };
}

export function newGoogleOAuthSecrets() {
  return {
    state: generateSecureToken(24),
    codeVerifier: generateSecureToken(32),
    nonce: generateSecureToken(16),
  };
}

const GOOGLE_JWKS = createRemoteJWKSet(
  new URL("https://www.googleapis.com/oauth2/v3/certs"),
);

export function googleProfileFromIdTokenClaims(claims: {
  sub?: unknown;
  email?: unknown;
  email_verified?: unknown;
  given_name?: unknown;
  family_name?: unknown;
  name?: unknown;
  picture?: unknown;
}): GoogleProfile {
  const sub = typeof claims.sub === "string" ? claims.sub : "";
  const email =
    typeof claims.email === "string" ? normalizeEmail(claims.email) : "";
  const emailVerified =
    claims.email_verified === true || claims.email_verified === "true";
  if (!sub || !email || !emailVerified) {
    throw new AppError("Google account email is not verified", 400, "google_email_unverified");
  }
  const firstName =
    (typeof claims.given_name === "string" && claims.given_name.trim()) ||
    email.split("@")[0] ||
    "Noirly";
  const lastName =
    (typeof claims.family_name === "string" && claims.family_name.trim()) || "User";
  const displayName =
    (typeof claims.name === "string" && claims.name.trim()) ||
    `${firstName} ${lastName}`.trim();
  return {
    sub,
    email,
    emailVerified: true,
    firstName,
    lastName,
    displayName,
    avatarUrl: typeof claims.picture === "string" ? claims.picture : null,
  };
}

export function googleIdTokenAudiences(): string[] {
  const env = getEnv();
  const mobile = (env.GOOGLE_MOBILE_CLIENT_IDS ?? "")
    .split(/[,\s]+/)
    .map((id) => id.trim())
    .filter(Boolean);
  return [...new Set([env.GOOGLE_CLIENT_ID, ...mobile].filter(Boolean) as string[])];
}

export async function verifyGoogleIdToken(input: {
  credential: string;
  nonce?: string | null;
}): Promise<GoogleProfile> {
  const audiences = googleIdTokenAudiences();
  if (audiences.length === 0) {
    throw new AppError("Google sign-in is not configured", 501, "google_not_configured");
  }

  let payload;
  try {
    const verified = await jwtVerify(input.credential, GOOGLE_JWKS, {
      issuer: ["https://accounts.google.com", "accounts.google.com"],
      audience: audiences,
    });
    payload = verified.payload;
  } catch {
    throw new AppError("Google sign-in failed", 401, "google_auth_failed");
  }

  if (
    input.nonce &&
    payload.nonce !== input.nonce
  ) {
    throw new AppError("Google sign-in failed", 401, "google_auth_failed");
  }

  return googleProfileFromIdTokenClaims(payload);
}
