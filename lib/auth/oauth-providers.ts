import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";
import { AppError } from "@/lib/api/errors";
import { normalizeEmail } from "@/lib/auth/user-mapper";
import type { ProviderProfile } from "@/lib/auth/provider-login";
import { getEnv } from "@/lib/config/env";

/**
 * Identity providers signed in with by a plain redirect (authorization code
 * with PKCE): Microsoft and GitHub. Each says how to send the person there
 * and how to turn what comes back into a profile. Google and Apple have
 * their own routes (One Tap; Apple's form post) but share the sign-in itself
 * (lib/auth/provider-login.ts).
 *
 * Whether the email is verified matters: only a verified address may find
 * an existing account or make a new one. Microsoft work and school accounts
 * can carry an address their organisation never proved, so theirs counts
 * only with Microsoft's own "domain owner verified" mark; such an account can
 * still be linked from settings, where the email isn't relied on.
 */

export const REDIRECT_PROVIDERS = ["microsoft", "github"] as const;
export type RedirectProvider = (typeof REDIRECT_PROVIDERS)[number];

export function isRedirectProvider(value: string): value is RedirectProvider {
  return (REDIRECT_PROVIDERS as readonly string[]).includes(value);
}

/** Microsoft's tenant for personal accounts: their addresses are Microsoft-verified. */
export const MICROSOFT_CONSUMER_TENANT = "9188040d-6c67-4c5b-b112-36a304b66dad";

let microsoftKeys: JWTVerifyGetKey = createRemoteJWKSet(new URL("https://login.microsoftonline.com/common/discovery/v2.0/keys"));
/** Tests swap in their own key set. */
export function setMicrosoftKeysForTests(keys: JWTVerifyGetKey | null) {
  microsoftKeys = keys ?? createRemoteJWKSet(new URL("https://login.microsoftonline.com/common/discovery/v2.0/keys"));
}

export function callbackUrl(provider: RedirectProvider) {
  return `${getEnv().APP_URL.replace(/\/$/, "")}/api/auth/oauth/${provider}/callback`;
}

export function isProviderConfigured(provider: RedirectProvider): boolean {
  const env = getEnv();
  return provider === "microsoft" ? Boolean(env.MICROSOFT_CLIENT_ID && env.MICROSOFT_CLIENT_SECRET) : Boolean(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET);
}

function notConfigured(provider: RedirectProvider): never {
  throw new AppError(`Sign in with ${provider === "microsoft" ? "Microsoft" : "GitHub"} is not configured`, 501, `${provider}_not_configured`);
}

export function buildAuthorizationUrl(provider: RedirectProvider, input: { state: string; nonce: string; codeChallenge: string; loginHint?: string }): string {
  if (!isProviderConfigured(provider)) notConfigured(provider);
  const env = getEnv();
  const url = provider === "microsoft"
    ? new URL(`https://login.microsoftonline.com/${encodeURIComponent(env.MICROSOFT_TENANT)}/oauth2/v2.0/authorize`)
    : new URL("https://github.com/login/oauth/authorize");
  url.searchParams.set("client_id", (provider === "microsoft" ? env.MICROSOFT_CLIENT_ID : env.GITHUB_CLIENT_ID)!);
  url.searchParams.set("redirect_uri", callbackUrl(provider));
  url.searchParams.set("state", input.state);
  url.searchParams.set("code_challenge", input.codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  if (provider === "microsoft") {
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid email profile");
    url.searchParams.set("nonce", input.nonce);
    url.searchParams.set("prompt", "select_account");
    if (input.loginHint) url.searchParams.set("login_hint", input.loginHint);
  } else {
    url.searchParams.set("scope", "read:user user:email");
    url.searchParams.set("allow_signup", "true");
    if (input.loginHint) url.searchParams.set("login", input.loginHint);
  }
  return url.toString();
}

function names(full: string | null | undefined, email: string, given?: unknown, family?: unknown) {
  const parts = (full ?? "").trim().split(/\s+/).filter(Boolean);
  const firstName = (typeof given === "string" && given.trim()) || parts[0] || email.split("@")[0] || "Noirly";
  const lastName = (typeof family === "string" && family.trim()) || (parts.length > 1 ? parts.slice(1).join(" ") : "User");
  return { firstName: firstName.slice(0, 100), lastName: lastName.slice(0, 100), displayName: ((full ?? "").trim() || `${firstName} ${lastName}`).slice(0, 150) };
}

/** A profile from a Microsoft id_token's claims. */
export async function microsoftProfileFromIdToken(idToken: string, nonce: string): Promise<ProviderProfile> {
  const env = getEnv();
  let payload;
  try {
    ({ payload } = await jwtVerify(idToken, microsoftKeys, { audience: env.MICROSOFT_CLIENT_ID }));
  } catch {
    throw new AppError("Microsoft sign-in failed", 401, "microsoft_auth_failed");
  }
  // Microsoft's issuer names the tenant the person signed in through.
  const tid = typeof payload.tid === "string" ? payload.tid : "";
  if (!tid || payload.iss !== `https://login.microsoftonline.com/${tid}/v2.0` || payload.nonce !== nonce || typeof payload.sub !== "string") {
    throw new AppError("Microsoft sign-in failed", 401, "microsoft_auth_failed");
  }
  const consumer = tid === MICROSOFT_CONSUMER_TENANT;
  const rawEmail = typeof payload.email === "string" ? payload.email : consumer && typeof payload.preferred_username === "string" ? payload.preferred_username : "";
  if (!rawEmail.includes("@")) throw new AppError("Microsoft didn't share an email address", 400, "microsoft_email_missing");
  const email = normalizeEmail(rawEmail);
  return {
    sub: `${tid}:${payload.sub}`,
    email,
    emailVerified: consumer || payload.xms_edov === true || payload.xms_edov === "1",
    ...names(typeof payload.name === "string" ? payload.name : null, email, payload.given_name, payload.family_name),
    avatarUrl: null,
  };
}

/** A profile from GitHub's API: its account id, and its primary address if GitHub has verified it. */
export function githubProfileFrom(user: { id?: unknown; login?: unknown; name?: unknown; avatar_url?: unknown }, emails: Array<{ email?: unknown; primary?: unknown; verified?: unknown }>): ProviderProfile {
  if (typeof user.id !== "number" && typeof user.id !== "string") throw new AppError("GitHub sign-in failed", 401, "github_auth_failed");
  const primary = emails.find((e) => e.primary === true && typeof e.email === "string") ?? emails.find((e) => e.verified === true && typeof e.email === "string");
  if (!primary) throw new AppError("GitHub didn't share an email address", 400, "github_email_missing");
  const email = normalizeEmail(String(primary.email));
  const login = typeof user.login === "string" ? user.login : null;
  return {
    sub: String(user.id),
    email,
    emailVerified: primary.verified === true,
    ...names(typeof user.name === "string" ? user.name : login, email),
    avatarUrl: typeof user.avatar_url === "string" ? user.avatar_url : null,
  };
}

async function postForm(url: string, body: Record<string, string>) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams(body),
    signal: AbortSignal.timeout(10_000),
  });
  return response.ok ? ((await response.json()) as Record<string, unknown>) : null;
}

/** Trades the code that came back for the person's profile. */
export async function exchangeCode(provider: RedirectProvider, input: { code: string; codeVerifier: string; nonce: string }): Promise<ProviderProfile> {
  if (!isProviderConfigured(provider)) notConfigured(provider);
  const env = getEnv();
  if (provider === "microsoft") {
    const tokens = await postForm(`https://login.microsoftonline.com/${encodeURIComponent(env.MICROSOFT_TENANT)}/oauth2/v2.0/token`, {
      grant_type: "authorization_code",
      code: input.code,
      redirect_uri: callbackUrl(provider),
      client_id: env.MICROSOFT_CLIENT_ID!,
      client_secret: env.MICROSOFT_CLIENT_SECRET!,
      code_verifier: input.codeVerifier,
    });
    if (typeof tokens?.id_token !== "string") throw new AppError("Microsoft sign-in failed", 401, "microsoft_auth_failed");
    return microsoftProfileFromIdToken(tokens.id_token, input.nonce);
  }
  const tokens = await postForm("https://github.com/login/oauth/access_token", {
    code: input.code,
    redirect_uri: callbackUrl(provider),
    client_id: env.GITHUB_CLIENT_ID!,
    client_secret: env.GITHUB_CLIENT_SECRET!,
    code_verifier: input.codeVerifier,
  });
  if (typeof tokens?.access_token !== "string") throw new AppError("GitHub sign-in failed", 401, "github_auth_failed");
  const headers = { authorization: `Bearer ${tokens.access_token}`, accept: "application/vnd.github+json", "user-agent": "noirly-identity" };
  const [userRes, emailsRes] = await Promise.all([
    fetch("https://api.github.com/user", { headers, signal: AbortSignal.timeout(10_000) }),
    fetch("https://api.github.com/user/emails", { headers, signal: AbortSignal.timeout(10_000) }),
  ]);
  if (!userRes.ok || !emailsRes.ok) throw new AppError("GitHub sign-in failed", 401, "github_auth_failed");
  return githubProfileFrom(await userRes.json(), await emailsRes.json());
}
