import { isIdle } from "@/lib/sessions/lifetime";
import { resolveAccessToken } from "@/lib/tokens/token-service";
import { Session } from "@/models/Session";

/**
 * Is the Identity session behind an app's sign-in still going? A cheap,
 * read-only answer apps can poll: one indexed lookup, and asking never counts
 * as activity, so polling can't keep an idle session alive.
 */
export type SessionCheck =
  | { active: false }
  | { active: true; sid: string; expires_at: number; auth_time: number };

const FIELDS = "_id sid appIds revokedAt expiresAt lastActivityAt createdAt idleTimeoutSeconds authenticatedAt";

type Found = {
  _id: unknown;
  sid?: string | null;
  revokedAt?: Date | null;
  expiresAt: Date;
  lastActivityAt?: Date | null;
  createdAt?: Date | null;
  idleTimeoutSeconds?: number | null;
  authenticatedAt?: Date | null;
};

function answer(session: Found | null): SessionCheck {
  const now = Date.now();
  if (!session || session.revokedAt || session.expiresAt.getTime() <= now || isIdle(session, now) || !session.sid) {
    return { active: false };
  }
  // It ends at the absolute end, or sooner if left idle.
  const idleEnd = session.idleTimeoutSeconds
    ? (session.lastActivityAt ?? session.createdAt ?? new Date(now)).getTime() + session.idleTimeoutSeconds * 1000
    : Infinity;
  return {
    active: true,
    sid: session.sid,
    expires_at: Math.floor(Math.min(session.expiresAt.getTime(), idleEnd) / 1000),
    auth_time: Math.floor((session.authenticatedAt ?? session.createdAt ?? new Date(now)).getTime() / 1000),
  };
}

/** For an app holding an access token: the session that token came from. */
export async function checkSessionForAccessToken(token: string): Promise<SessionCheck> {
  const record = await resolveAccessToken(token);
  if (!record) return { active: false };
  return answer(await Session.findById(record.sessionId).select(FIELDS).lean());
}

/**
 * For an authenticated app asking by `sid` (from its ID token). Only sessions
 * that signed in to that app are answered for; any other looks inactive.
 */
export async function checkSessionBySid(clientId: string, sid: string): Promise<SessionCheck> {
  const session = await Session.findOne({ sid, appIds: clientId }).select(FIELDS).lean();
  return answer(session);
}
