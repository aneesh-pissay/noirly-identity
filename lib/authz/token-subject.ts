import { OAuthError } from "@/lib/api/errors";
import { hashToken } from "@/lib/security/crypto";
import { isIdle } from "@/lib/sessions/lifetime";
import { machineTokenIsLive } from "@/lib/oauth/client-credentials";
import { AccessToken } from "@/models/AccessToken";
import { ServiceAccount } from "@/models/Authz";
import { Session } from "@/models/Session";
import type { Subject } from "@/lib/authz/engine";

/**
 * Who a bearer token speaks for, for the permissions API: a person in the
 * organization the token is scoped to (opaque or JWT access token), or a
 * service account (its client credentials token) in its own organization.
 * Anything not live is refused as `invalid_token`.
 */
export async function subjectForToken(token: string): Promise<{ organizationId: string; subject: Subject; sessionId: unknown }> {
  const record = token.length <= 4096 ? await AccessToken.findOne({ tokenHash: hashToken(token) }).lean() : null;
  if (!record || record.revokedAt || record.expiresAt <= new Date()) throw new OAuthError("invalid_token", "Access token is invalid or expired", 401);

  if (record.kind === "machine") {
    if (!(await machineTokenIsLive(record))) throw new OAuthError("invalid_token", "Access token is invalid or expired", 401);
    const account = await ServiceAccount.findOne({ clientId: record.clientId, disabledAt: null }).lean();
    if (!account) throw new OAuthError("insufficient_scope", "Only service accounts have permissions of their own", 403);
    return { organizationId: String(account.organizationId), subject: { type: "service", id: String(account._id) }, sessionId: null };
  }

  const session = record.sessionId ? await Session.findById(record.sessionId).select("revokedAt expiresAt lastActivityAt createdAt idleTimeoutSeconds").lean() : null;
  if (!session || session.revokedAt || session.expiresAt <= new Date() || isIdle(session)) throw new OAuthError("invalid_token", "Access token is invalid or expired", 401);
  if (!record.organizationId) {
    throw new OAuthError("invalid_request", "This token isn't scoped to an organization; sign in with organization= to check permissions", 400);
  }
  return { organizationId: String(record.organizationId), subject: { type: "user", id: String(record.userId) }, sessionId: record.sessionId };
}
