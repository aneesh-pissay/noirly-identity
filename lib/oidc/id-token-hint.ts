import { createLocalJWKSet, jwtVerify } from "jose";
import { getEnv } from "@/lib/config/env";
import { getJwks } from "@/lib/oidc/keys";

/**
 * `id_token_hint` (OIDC Core 3.1.2.1, RP-Initiated Logout 2): an ID token
 * Identity issued earlier. It may have expired, so only the signature, issuer
 * and `typ` are checked. Returns who it names and which app it was for, or
 * null when it isn't one of Identity's ID tokens (a hint is then ignored).
 */
export async function readIdTokenHint(hint: string | null | undefined): Promise<{ sub: string; clientId: string } | null> {
  if (!hint) return null;
  try {
    const { payload } = await jwtVerify(hint, createLocalJWKSet(await getJwks()), {
      issuer: getEnv().OIDC_ISSUER.replace(/\/$/, ""),
      algorithms: ["RS256"],
      typ: "JWT",
      // An old ID token is still a fine hint.
      currentDate: new Date(0),
    });
    const aud = Array.isArray(payload.aud) ? payload.aud[0] : payload.aud;
    return typeof payload.sub === "string" && typeof aud === "string" ? { sub: payload.sub, clientId: aud } : null;
  } catch {
    return null;
  }
}

export async function subjectFromIdTokenHint(hint: string | null | undefined): Promise<string | null> {
  return (await readIdTokenHint(hint))?.sub ?? null;
}
