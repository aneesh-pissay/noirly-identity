import { preferenceClaims } from "@/lib/account/preferences";
import type { UserDocument } from "@/models/User";

type ClaimUser = Pick<UserDocument, "email" | "emailVerified" | "displayName" | "firstName" | "lastName" | "avatarUrl" | "roles" | "locale" | "zoneinfo" | "accessibility">;

/** The claims a set of granted scopes allows, the same in ID tokens and UserInfo. */
export function scopedClaims(user: ClaimUser, scopes: Set<string>): Record<string, unknown> {
  const claims: Record<string, unknown> = {};
  if (scopes.has("email")) {
    claims.email = user.email;
    claims.email_verified = user.emailVerified;
  }
  if (scopes.has("profile")) {
    claims.name = user.displayName;
    claims.given_name = user.firstName;
    claims.family_name = user.lastName;
    if (user.avatarUrl) claims.picture = user.avatarUrl;
    Object.assign(claims, preferenceClaims(user));
  }
  // A plain copy: a Mongoose array can't be cloned into a JWT.
  if (scopes.has("roles")) claims.roles = [...user.roles];
  return claims;
}
