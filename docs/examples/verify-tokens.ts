/**
 * Reference token checks for apps and APIs using Noirly Identity.
 * Copy this file; it needs only `jose`. docs/TOKEN-VALIDATION.md explains each
 * check, and tests/token-validation.test.ts runs every one against real
 * Identity tokens, including the ways they should fail.
 */
import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from "jose";

export type IdentityKeys = {
  /** Identity's issuer, exactly as discovery gives it (no trailing slash). */
  issuer: string;
  /** Identity's published keys. Use `identityKeys(issuer)`; tests pass a local set. */
  jwks: JWTVerifyGetKey;
  /** Only for tests: the time to check against. */
  currentDate?: Date;
};

/** Caches Identity's keys and refetches once when a token names a key it hasn't seen. */
export function identityKeys(issuer: string): IdentityKeys {
  return { issuer, jwks: createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`)) };
}

/** Clock skew allowed between Identity and you. */
const CLOCK_TOLERANCE_SECONDS = 60;

export class TokenRejected extends Error {}

async function verify(token: string, keys: IdentityKeys, options: { audience: string; typ: string; required: string[] }) {
  let result;
  try {
    result = await jwtVerify(token, keys.jwks, {
      issuer: keys.issuer,
      audience: options.audience,
      // Only RS256: never `none`, never an HMAC keyed with the public key.
      algorithms: ["RS256"],
      typ: options.typ,
      requiredClaims: options.required,
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
      currentDate: keys.currentDate,
    });
  } catch (error) {
    throw new TokenRejected(error instanceof Error ? error.message : "Invalid token");
  }
  // jose checks `exp` but not an `iat` in the future; a token can't be issued after now.
  const now = Math.floor((keys.currentDate ?? new Date()).getTime() / 1000);
  if (typeof result.payload.iat !== "number" || result.payload.iat > now + CLOCK_TOLERANCE_SECONDS) {
    throw new TokenRejected("Token issued in the future");
  }
  return result;
}

/**
 * An ID token, after the code exchange (or a refresh). `nonce` is the value
 * you stored when you sent the person to sign in; `maxAgeSeconds` and `acr`
 * repeat what you asked for, since a token proves it, not the request.
 */
export async function verifyIdToken(
  token: string,
  keys: IdentityKeys & { clientId: string },
  expected: { nonce?: string; maxAgeSeconds?: number; acr?: string[] } = {},
): Promise<JWTPayload> {
  const { payload } = await verify(token, keys, { audience: keys.clientId, typ: "JWT", required: ["sub", "iat", "exp", "auth_time", "sid"] });
  // Identity names one audience; several would need `azp` to be you.
  if (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== keys.clientId) throw new TokenRejected("Token is for someone else");
  if (expected.nonce !== undefined && payload.nonce !== expected.nonce) throw new TokenRejected("nonce does not match");
  const now = Math.floor((keys.currentDate ?? new Date()).getTime() / 1000);
  if (expected.maxAgeSeconds !== undefined && now - Number(payload.auth_time) > expected.maxAgeSeconds + CLOCK_TOLERANCE_SECONDS) {
    throw new TokenRejected("Sign-in is older than max_age");
  }
  if (expected.acr?.length && !expected.acr.includes(String(payload.acr))) throw new TokenRejected("Sign-in is not strong enough");
  return payload;
}

/**
 * A JWT access token at your API (RFC 9068; tokens asked for with
 * `resource=`). `audience` is your API's registered identifier.
 */
export async function verifyAccessToken(
  token: string,
  keys: IdentityKeys & { audience: string },
  requiredScopes: string[] = [],
): Promise<JWTPayload & { scope: string; client_id: string }> {
  const { payload } = await verify(token, keys, { audience: keys.audience, typ: "at+jwt", required: ["sub", "client_id", "scope", "jti", "iat", "exp"] });
  const granted = new Set(String(payload.scope).split(" "));
  const missing = requiredScopes.filter((s) => !granted.has(s));
  if (missing.length) throw new TokenRejected(`Missing scope: ${missing.join(" ")}`);
  return payload as JWTPayload & { scope: string; client_id: string };
}

export const BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";

/**
 * A back-channel logout token. `seen` remembers `jti`s for a few minutes and
 * says whether one came before, so a replay is refused. Returns what to end:
 * the session named by `sid`, or every session of `sub` when there's no `sid`.
 */
export async function verifyLogoutToken(
  token: string,
  keys: IdentityKeys & { clientId: string },
  seen: (jti: string) => boolean,
): Promise<{ sub: string; sid: string | null }> {
  const { payload } = await verify(token, keys, { audience: keys.clientId, typ: "logout+jwt", required: ["sub", "iat", "exp", "jti", "events"] });
  const events = payload.events as Record<string, unknown> | undefined;
  if (!events || typeof events[BACKCHANNEL_LOGOUT_EVENT] !== "object") throw new TokenRejected("Not a logout token");
  // A logout token must never be mistaken for an ID token, or the reverse.
  if ("nonce" in payload) throw new TokenRejected("Logout tokens carry no nonce");
  if (seen(String(payload.jti))) throw new TokenRejected("Logout token replayed");
  return { sub: String(payload.sub), sid: typeof payload.sid === "string" ? payload.sid : null };
}
