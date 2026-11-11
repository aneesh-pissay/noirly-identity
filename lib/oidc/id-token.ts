import { SignJWT } from "jose";
import { getEnv } from "@/lib/config/env";
import { getSigningKeys } from "@/lib/oidc/keys";
import type { UserDocument } from "@/models/User";
import { scopedClaims } from "@/lib/oidc/claims";
import { acrFor, amrFor } from "@/lib/auth/acr";
import { sessionSid } from "@/lib/oidc/sid";
import { Session } from "@/models/Session";
import { organizationsClaim } from "@/lib/oauth/org-context";
import { permissionsClaim } from "@/lib/authz/delivery";

export async function createIdToken(input: {
  user: UserDocument;
  clientId: string;
  scope: string;
  nonce?: string | null;
  authTime: Date;
  /** How the session was signed in: becomes `amr` and `acr` (lib/auth/acr.ts). */
  methods?: readonly string[];
  /** The Identity session behind it: becomes `sid`, which logout tokens name. */
  sessionId?: unknown;
  /** Organization context claims (org_id, org_slug, org_role). */
  organization?: Record<string, string> | null;
}): Promise<string> {
  const env = getEnv();
  const keys = await getSigningKeys();
  const scopes = new Set(input.scope.split(/\s+/));
  const now = Math.floor(Date.now() / 1000);

  const claims: Record<string, unknown> = {
    auth_time: Math.floor(input.authTime.getTime() / 1000),
    ...scopedClaims(input.user, scopes),
  };
  if (input.methods?.length) {
    claims.amr = amrFor(input.methods);
    claims.acr = acrFor(input.methods);
  }

  if (input.sessionId) {
    claims.sid = sessionSid(input.sessionId);
    // Sessions from before `sid` was stored learn it here, for the session check.
    await Session.updateOne({ _id: input.sessionId, sid: null }, { $set: { sid: claims.sid } });
  }

  if (input.organization) Object.assign(claims, input.organization);
  if (input.organization?.org_id && scopes.has("permissions")) {
    claims.permissions = await permissionsClaim(input.organization.org_id, String(input.user._id), input.sessionId);
  }
  if (scopes.has("organizations")) claims.organizations = await organizationsClaim(input.user._id);

  if (input.nonce) {
    claims.nonce = input.nonce;
  }

  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: keys.kid, typ: "JWT" })
    .setIssuer(env.OIDC_ISSUER)
    .setSubject(String(input.user._id))
    .setAudience(input.clientId)
    .setIssuedAt(now)
    .setExpirationTime(now + env.ACCESS_TOKEN_TTL_SECONDS)
    .sign(keys.privateKey);
}
