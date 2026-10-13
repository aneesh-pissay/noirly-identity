import { isBlockedUser } from "@/lib/auth/user-policy";
import { OAuthError } from "@/lib/api/errors";
import { resolveAccessToken } from "@/lib/tokens/token-service";
import { User } from "@/models/User";

export function extractBearerToken(request: Request): string | null {
  const header = request.headers.get("authorization");
  if (!header?.toLowerCase().startsWith("bearer ")) {
    return null;
  }
  return header.slice(7).trim() || null;
}

export async function buildUserInfo(accessToken: string) {
  const token = await resolveAccessToken(accessToken);
  if (!token) {
    throw new OAuthError("invalid_token", "Access token is invalid or expired", 401);
  }

  const user = await User.findById(token.userId);
  if (!user || isBlockedUser(user)) {
    throw new OAuthError("invalid_token", "Access token is invalid or expired", 401);
  }

  const scopes = new Set(token.scope.split(/\s+/));
  const claims: Record<string, unknown> = {
    sub: String(user._id),
  };

  if (scopes.has("email")) {
    claims.email = user.email;
    claims.email_verified = user.emailVerified;
  }

  if (scopes.has("profile")) {
    claims.name = user.displayName;
    claims.given_name = user.firstName;
    claims.family_name = user.lastName;
    if (user.avatarUrl) {
      claims.picture = user.avatarUrl;
    }
  }

  if (scopes.has("roles")) {
    claims.roles = user.roles;
  }

  return claims;
}
