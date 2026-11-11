import { z } from "zod";
import { OAuthError } from "@/lib/api/errors";

/**
 * The OpenID Connect `claims` request parameter (Core §5.5), held to one rule:
 * claims follow scopes, and scopes follow consent. A claim asked for on its
 * own becomes a request for the scope that carries it, so the consent screen
 * and the grant cover it like any other; it's only granted when the app is
 * allowed that scope at all. The parameter can't widen what the person agreed
 * to. Claims Identity doesn't know are ignored, as the spec asks.
 *
 * Two members have meaning beyond that:
 * - `acr` with `essential: true` and `values`: a step-up, like `acr_values`.
 * - `sub` with a `value`: only that account may answer.
 */

/** Claims every ID token carries, whatever the scopes. */
export const ID_TOKEN_BASE_CLAIMS = ["iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "sid", "acr", "amr"] as const;

/** Which scope carries each claim (lib/oidc/claims.ts). */
export const CLAIM_SCOPE: Record<string, string> = {
  email: "email",
  email_verified: "email",
  name: "profile",
  given_name: "profile",
  family_name: "profile",
  picture: "profile",
  locale: "profile",
  zoneinfo: "profile",
  noirly_accessibility: "profile",
  roles: "roles",
};

const claimSpec = z.union([
  z.null(),
  z.object({ essential: z.boolean().optional(), value: z.unknown().optional(), values: z.array(z.unknown()).max(20).optional() }).passthrough(),
]);
const member = z.record(z.string().max(100), claimSpec).optional();
const claimsSchema = z.object({ userinfo: member, id_token: member }).passthrough();

export type ClaimsRequest = {
  /** Scopes the requested claims need. */
  scopes: string[];
  /** `acr` asked for as essential: the levels that would do. */
  essentialAcr: string[];
  /** `sub` asked for by value: only this account may answer. */
  sub: string | null;
};

export function parseClaimsRequest(raw: string | null | undefined): ClaimsRequest {
  const empty: ClaimsRequest = { scopes: [], essentialAcr: [], sub: null };
  if (!raw) return empty;
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    throw new OAuthError("invalid_request", "claims must be a JSON object");
  }
  const parsed = claimsSchema.safeParse(json);
  if (!parsed.success) throw new OAuthError("invalid_request", "claims is not a valid claims request");

  const scopes = new Set<string>();
  const result: ClaimsRequest = { ...empty, essentialAcr: [] };
  for (const requested of [parsed.data.userinfo, parsed.data.id_token]) {
    for (const [name, spec] of Object.entries(requested ?? {})) {
      if (CLAIM_SCOPE[name]) scopes.add(CLAIM_SCOPE[name]);
      if (name === "acr" && spec?.essential) {
        const values = spec.values ?? (spec.value !== undefined ? [spec.value] : []);
        result.essentialAcr.push(...values.filter((v): v is string => typeof v === "string"));
      }
      if (name === "sub" && typeof spec?.value === "string") {
        if (result.sub && result.sub !== spec.value) throw new OAuthError("invalid_request", "claims asks for two different sub values");
        result.sub = spec.value;
      }
    }
  }
  result.scopes = [...scopes];
  return result;
}

/** The scopes to add for the claims asked for, limited to what the app may ever be given. */
export function scopesForClaims(request: ClaimsRequest, alreadyRequested: string[], allowedScopes: readonly string[]) {
  return request.scopes.filter((s) => allowedScopes.includes(s) && !alreadyRequested.includes(s));
}
