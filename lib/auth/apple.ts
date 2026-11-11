import { createHash } from "node:crypto";
import { createRemoteJWKSet, importPKCS8, jwtVerify, SignJWT, type JWTVerifyGetKey } from "jose";
import { AppError } from "@/lib/api/errors";
import { normalizeEmail } from "@/lib/auth/user-mapper";
import { loginWithProviderProfile, type ProviderLoginMeta, type ProviderProfile } from "@/lib/auth/provider-login";
import { getEnv } from "@/lib/config/env";

/**
 * Sign in with Apple, on the web and from native apps.
 *
 * Web: the usual authorization code flow, except Apple posts its answer
 * back (response_mode=form_post) and authenticates Identity with a client
 * secret that is itself a short-lived JWT signed by the team's key. Native:
 * the app gets an id_token from Apple and sends it here. Either way the
 * id_token is checked against Apple's keys, issuer, audience and nonce.
 *
 * Apple sends the person's name only the first time they sign in to an app,
 * and may give a private relay address (…@privaterelay.appleid.com) instead
 * of their own; both are taken as Apple gives them.
 */

const APPLE_ISSUER = "https://appleid.apple.com";
let appleKeys: JWTVerifyGetKey = createRemoteJWKSet(new URL(`${APPLE_ISSUER}/auth/keys`));

/** Tests swap in their own key set. */
export function setAppleKeysForTests(keys: JWTVerifyGetKey | null) {
  appleKeys = keys ?? createRemoteJWKSet(new URL(`${APPLE_ISSUER}/auth/keys`));
}

export function isAppleConfigured(): boolean {
  const env = getEnv();
  return Boolean(env.APPLE_CLIENT_ID && env.APPLE_TEAM_ID && env.APPLE_KEY_ID && env.APPLE_PRIVATE_KEY);
}

export function appleCallbackUrl(): string {
  return `${getEnv().APP_URL.replace(/\/$/, "")}/api/auth/apple/callback`;
}

export function buildAppleAuthorizationUrl(input: { state: string; nonce: string }): string {
  const env = getEnv();
  if (!isAppleConfigured()) throw new AppError("Sign in with Apple is not configured", 501, "apple_not_configured");
  const url = new URL(`${APPLE_ISSUER}/auth/authorize`);
  url.searchParams.set("client_id", env.APPLE_CLIENT_ID!);
  url.searchParams.set("redirect_uri", appleCallbackUrl());
  url.searchParams.set("response_type", "code");
  // Asking for name or email makes Apple post the answer back rather than redirect.
  url.searchParams.set("scope", "name email");
  url.searchParams.set("response_mode", "form_post");
  url.searchParams.set("state", input.state);
  url.searchParams.set("nonce", input.nonce);
  return url.toString();
}

/** The client secret Apple asks for: a JWT signed with the team's key, good for five minutes. */
export async function appleClientSecret(): Promise<string> {
  const env = getEnv();
  if (!isAppleConfigured()) throw new AppError("Sign in with Apple is not configured", 501, "apple_not_configured");
  const key = await importPKCS8(env.APPLE_PRIVATE_KEY!, "ES256");
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: env.APPLE_KEY_ID! })
    .setIssuer(env.APPLE_TEAM_ID!)
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .setAudience(APPLE_ISSUER)
    .setSubject(env.APPLE_CLIENT_ID!)
    .sign(key);
}

/** The name Apple sends once, on the first sign-in, as the `user` form field. */
export type AppleName = { firstName?: string | null; lastName?: string | null };

export function parseAppleUser(raw: string | null | undefined): AppleName {
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw) as { name?: { firstName?: unknown; lastName?: unknown } };
    const clean = (value: unknown) => (typeof value === "string" ? value.trim().slice(0, 100) || null : null);
    return { firstName: clean(parsed.name?.firstName), lastName: clean(parsed.name?.lastName) };
  } catch {
    return {};
  }
}

/** A profile from Apple's id_token claims (and the name, when Apple sent one). */
export function appleProfileFromClaims(claims: { sub?: unknown; email?: unknown; email_verified?: unknown }, name: AppleName = {}): ProviderProfile {
  const sub = typeof claims.sub === "string" ? claims.sub : "";
  const email = typeof claims.email === "string" ? normalizeEmail(claims.email) : "";
  const emailVerified = claims.email_verified === true || claims.email_verified === "true";
  if (!sub || !email) throw new AppError("Apple didn't share an email address. Allow it and try again.", 400, "apple_email_missing");
  const firstName = name.firstName || email.split("@")[0] || "Noirly";
  const lastName = name.lastName || "User";
  return { sub, email, emailVerified, firstName, lastName, displayName: `${firstName} ${lastName}`.trim(), avatarUrl: null };
}

function audiences(includeNative: boolean): string[] {
  const env = getEnv();
  const native = includeNative ? (env.APPLE_MOBILE_CLIENT_IDS ?? "").split(/[,\s]+/).filter(Boolean) : [];
  return [...new Set([env.APPLE_CLIENT_ID, ...native].filter(Boolean) as string[])];
}

/**
 * Checks an id_token from Apple. `nonce` is what the caller generated:
 * the web sends it to Apple as is; native apps conventionally send its
 * SHA-256, so either form is accepted.
 */
export async function verifyAppleIdToken(input: { idToken: string; nonce?: string | null; native?: boolean; name?: AppleName }): Promise<ProviderProfile> {
  const aud = audiences(Boolean(input.native));
  if (aud.length === 0) throw new AppError("Sign in with Apple is not configured", 501, "apple_not_configured");
  let payload;
  try {
    ({ payload } = await jwtVerify(input.idToken, appleKeys, { issuer: APPLE_ISSUER, audience: aud }));
  } catch {
    throw new AppError("Apple sign-in failed", 401, "apple_auth_failed");
  }
  if (input.nonce) {
    const hashed = createHash("sha256").update(input.nonce).digest("hex");
    if (payload.nonce !== input.nonce && payload.nonce !== hashed) throw new AppError("Apple sign-in failed", 401, "apple_auth_failed");
  }
  return appleProfileFromClaims(payload, input.name);
}

/** Web: trades the code Apple posted back for its id_token, and checks it. */
export async function exchangeAppleCode(input: { code: string; nonce: string; name?: AppleName }): Promise<ProviderProfile> {
  const env = getEnv();
  const response = await fetch(`${APPLE_ISSUER}/auth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: input.code,
      redirect_uri: appleCallbackUrl(),
      client_id: env.APPLE_CLIENT_ID ?? "",
      client_secret: await appleClientSecret(),
    }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new AppError("Apple sign-in failed", 401, "apple_auth_failed");
  const tokens = (await response.json()) as { id_token?: string };
  if (!tokens.id_token) throw new AppError("Apple sign-in failed", 401, "apple_auth_failed");
  return verifyAppleIdToken({ idToken: tokens.id_token, nonce: input.nonce, name: input.name });
}

export function loginWithAppleProfile(profile: ProviderProfile, meta: ProviderLoginMeta) {
  return loginWithProviderProfile("apple", profile, meta);
}
