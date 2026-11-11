import { randomUUID } from "node:crypto";
import { SignJWT } from "jose";
import { getEnv } from "@/lib/config/env";
import { acrFor, amrFor } from "@/lib/auth/acr";
import { getSigningKeys } from "@/lib/oidc/keys";
import { sessionSid } from "@/lib/oidc/sid";

/**
 * An access token for one API, as a JWT (RFC 9068): header `typ` `at+jwt`,
 * signed with Identity's current key (JWKS), `aud` the API's identifier. The
 * API checks it offline: signature, `iss`, `aud`, `exp`, then `scope`.
 */
export async function signJwtAccessToken(input: {
  audience: string;
  clientId: string;
  userId: string;
  sessionId: unknown;
  scope: string;
  expiresIn: number;
  authTime: Date;
  methods: readonly string[];
  /** Organization context claims (org_id, org_slug, org_role). */
  extraClaims?: Record<string, unknown>;
}): Promise<string> {
  const keys = await getSigningKeys();
  const now = Math.floor(Date.now() / 1000);
  const claims: Record<string, unknown> = {
    client_id: input.clientId,
    scope: input.scope,
    sid: sessionSid(input.sessionId),
    auth_time: Math.floor(input.authTime.getTime() / 1000),
  };
  if (input.extraClaims) Object.assign(claims, input.extraClaims);
  if (input.methods.length) {
    claims.amr = amrFor(input.methods);
    claims.acr = acrFor(input.methods);
  }
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: keys.kid, typ: "at+jwt" })
    .setIssuer(getEnv().OIDC_ISSUER)
    .setSubject(input.userId)
    .setAudience(input.audience)
    .setIssuedAt(now)
    .setExpirationTime(now + input.expiresIn)
    .setJti(randomUUID())
    .sign(keys.privateKey);
}
