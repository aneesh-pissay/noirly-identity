import { getEnv } from "@/lib/config/env";
import { isBlockedUser } from "@/lib/auth/user-policy";
import { sessionSid } from "@/lib/oidc/sid";
import { isIdle } from "@/lib/sessions/lifetime";
import { hashToken } from "@/lib/security/crypto";
import { AccessToken } from "@/models/AccessToken";
import { RefreshToken } from "@/models/RefreshToken";
import { Session } from "@/models/Session";
import { User } from "@/models/User";
import { machineTokenIsLive } from "@/lib/oauth/client-credentials";
import { orgClaims } from "@/lib/oauth/org-context";

/**
 * Token introspection (RFC 7662): lets a resource server ask whether a token
 * it was handed is live, and what it allows. Opaque tokens can't be checked
 * any other way.
 *
 * A token is active only while it is unexpired and unrevoked, its Identity
 * session is live (not ended, expired or idle), and its account is usable.
 * - Access tokens: any authenticated confidential app (an API is one) may ask.
 * - Refresh tokens: only the app they were issued to; anyone else hears inactive.
 */
export type Introspection =
  | { active: false }
  | {
      active: true;
      token_type: "Bearer" | "refresh_token";
      scope: string;
      client_id: string;
      sub: string;
      iss: string;
      iat: number;
      exp: number;
      /** Absent for an app's own (machine) token: no person, no session. */
      sid?: string;
      auth_time?: number;
      /** For a JWT access token: the API it's for. */
      aud?: string;
      /** Organization context. */
      org_id?: string;
      org_role?: string;
    };

const INACTIVE = { active: false } as const;
const seconds = (date: Date) => Math.floor(date.getTime() / 1000);

type Found = { clientId: string; userId: unknown; sessionId: unknown; scope: string; expiresAt: Date; revokedAt?: Date | null; createdAt?: Date | null; audience?: string | null; organizationId?: unknown };

async function describe(token: Found, tokenType: "Bearer" | "refresh_token"): Promise<Introspection> {
  const now = new Date();
  if (token.revokedAt || token.expiresAt <= now) return INACTIVE;
  const [session, user] = await Promise.all([
    Session.findById(token.sessionId).select("revokedAt expiresAt lastActivityAt createdAt idleTimeoutSeconds authenticatedAt").lean(),
    User.findById(token.userId).select("email status").lean(),
  ]);
  if (!session || session.revokedAt || session.expiresAt <= now || isIdle(session, now.getTime())) return INACTIVE;
  if (!user || user.status !== "active" || isBlockedUser(user)) return INACTIVE;
  const org = await orgPart(token);
  if (!org) return INACTIVE;
  return {
    active: true,
    token_type: tokenType,
    scope: token.scope,
    client_id: token.clientId,
    sub: String(token.userId),
    iss: getEnv().OIDC_ISSUER,
    iat: seconds(token.createdAt ?? now),
    // Never later than the session it depends on.
    exp: seconds(token.expiresAt < session.expiresAt ? token.expiresAt : session.expiresAt),
    sid: sessionSid(session._id),
    auth_time: seconds(session.authenticatedAt ?? session.createdAt),
    ...(token.audience ? { aud: token.audience } : {}),
    ...org,
  };
}

/** Organization context, checked live: someone who left makes the token inactive (null). */
async function orgPart(token: Found): Promise<{ org_id?: string; org_role?: string } | null> {
  if (!token.organizationId) return {};
  try {
    const claims = await orgClaims(token.organizationId, token.userId);
    return { org_id: claims.org_id, org_role: claims.org_role };
  } catch {
    return null;
  }
}

/** An app's own token (client credentials): `sub` is the app. */
async function describeMachineToken(token: { clientId: string; scope: string; audience?: string | null; revokedAt?: Date | null; expiresAt: Date; createdAt?: Date | null }): Promise<Introspection> {
  if (!(await machineTokenIsLive(token))) return INACTIVE;
  return {
    active: true,
    token_type: "Bearer",
    scope: token.scope,
    client_id: token.clientId,
    sub: token.clientId,
    iss: getEnv().OIDC_ISSUER,
    iat: seconds(token.createdAt ?? new Date()),
    exp: seconds(token.expiresAt),
    ...(token.audience ? { aud: token.audience } : {}),
  };
}

export async function introspectToken(token: string, askingClientId: string, hint?: string | null): Promise<Introspection> {
  // JWT access tokens run to a kilobyte or so; opaque ones are short.
  if (!token || token.length > 4096) return INACTIVE;
  const tokenHash = hashToken(token);
  // The hint only sets the order to look in (RFC 7662 §2.1).
  const order = hint === "refresh_token" ? (["refresh", "access"] as const) : (["access", "refresh"] as const);
  for (const kind of order) {
    if (kind === "access") {
      const access = await AccessToken.findOne({ tokenHash }).lean();
      if (access?.kind === "machine") return describeMachineToken(access);
      if (access?.userId && access.sessionId) return describe({ ...access, userId: access.userId, sessionId: access.sessionId }, "Bearer");
      if (access) return INACTIVE;
    } else {
      const refresh = await RefreshToken.findOne({ tokenHash }).lean();
      if (refresh) {
        if (refresh.clientId !== askingClientId) return INACTIVE;
        // A rotated-away token is spent, even before reuse is noticed.
        if (refresh.replacedByTokenHash) return INACTIVE;
        return describe(refresh, "refresh_token");
      }
    }
  }
  return INACTIVE;
}
