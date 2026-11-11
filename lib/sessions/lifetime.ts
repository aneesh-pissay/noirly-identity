import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { getEnv } from "@/lib/config/env";
import { recordEvent, type RequestMeta } from "@/lib/audit/event-log";
import { Session } from "@/models/Session";
import { User } from "@/models/User";
import { Organization } from "@/models/Organization";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { ABSOLUTE_MIN_SECONDS, IDLE_MAX_SECONDS, IDLE_MIN_SECONDS, type SessionPolicy } from "@/lib/sessions/lifetime-choices";

export type { SessionPolicy };

/** The longest absolute lifetime allowed: Identity's own default. */
export function absoluteMaxSeconds() {
  return getEnv().SESSION_TTL_SECONDS;
}

export function validatePolicy(policy: SessionPolicy): SessionPolicy {
  const { idleSeconds, absoluteSeconds } = policy;
  if (idleSeconds !== null && (!Number.isInteger(idleSeconds) || idleSeconds < IDLE_MIN_SECONDS || idleSeconds > IDLE_MAX_SECONDS)) {
    throw new AppError("Choose an idle limit between 15 minutes and 30 days", 400, "invalid_request");
  }
  if (absoluteSeconds !== null && (!Number.isInteger(absoluteSeconds) || absoluteSeconds < ABSOLUTE_MIN_SECONDS || absoluteSeconds > absoluteMaxSeconds())) {
    throw new AppError("Choose a session length between an hour and Identity's default", 400, "invalid_request");
  }
  if (idleSeconds !== null && absoluteSeconds !== null && idleSeconds > absoluteSeconds) {
    throw new AppError("The idle limit can't be longer than the session itself", 400, "invalid_request");
  }
  return { idleSeconds, absoluteSeconds };
}

/** The account's own choice (the account page), before any organization's. */
export async function accountSessionPolicy(userId: Types.ObjectId | string): Promise<SessionPolicy> {
  const user = await User.findById(userId).select("sessionPolicy").lean();
  return {
    idleSeconds: user?.sessionPolicy?.idleSeconds ?? null,
    absoluteSeconds: user?.sessionPolicy?.absoluteSeconds ?? null,
  };
}

const stricter = (a: number | null, b: number | null) => (a === null ? b : b === null ? a : Math.min(a, b));

/**
 * The policy new and existing sessions of this account follow: the strictest
 * of the account's own and every organization it belongs to
 * (lib/spaces/org-security.ts).
 */
export async function sessionPolicyFor(userId: Types.ObjectId | string): Promise<SessionPolicy> {
  const own = await accountSessionPolicy(userId);
  const memberships = await OrganizationMembership.find({ userId: new Types.ObjectId(String(userId)) }).select("organizationId").lean();
  if (!memberships.length) return own;
  const orgs = await Organization.find({ _id: { $in: memberships.map((m) => m.organizationId) }, status: "active" }).select("sessionPolicy").lean();
  return orgs.reduce<SessionPolicy>(
    (policy, org) => ({
      idleSeconds: stricter(policy.idleSeconds, org.sessionPolicy?.idleSeconds ?? null),
      absoluteSeconds: stricter(policy.absoluteSeconds, org.sessionPolicy?.absoluteSeconds ?? null),
    }),
    own,
  );
}

/** True when a session has gone unused longer than its idle limit. */
export function isIdle(session: { idleTimeoutSeconds?: number | null; lastActivityAt?: Date | null; createdAt?: Date | null }, now = Date.now()) {
  if (!session.idleTimeoutSeconds) return false;
  const last = (session.lastActivityAt ?? session.createdAt)?.getTime() ?? 0;
  return now - last > session.idleTimeoutSeconds * 1000;
}

/**
 * Saves the account's policy and applies it to every live session at once:
 * each ends at sign-in plus the new length (sooner, never later than it would
 * have). This session restarts its clock, since changing this needs a fresh
 * sign-in, so the change can't sign you out on the spot.
 */
export async function setSessionPolicy(userId: string, input: SessionPolicy, currentSessionId: string, meta: RequestMeta = {}) {
  const own = validatePolicy(input);
  await User.updateOne({ _id: userId }, { $set: { sessionPolicy: own } });
  await applySessionPolicy(userId, currentSessionId);
  await recordEvent({ action: "account.session_policy_changed", subjectId: userId, request: meta, data: { ...own } });
  return own;
}

/**
 * Applies the account's effective policy (its own and its organizations') to
 * every live session: each ends at sign-in plus the length (sooner, never
 * later). `currentSessionId`, if given, restarts its clock (the account page,
 * after a fresh sign-in).
 */
export async function applySessionPolicy(userId: string, currentSessionId: string | null = null) {
  const policy = await sessionPolicyFor(userId);
  const now = Date.now();
  const sessions = await Session.find({ userId, revokedAt: null, expiresAt: { $gt: new Date(now) } }).select("createdAt expiresAt").lean();
  const defaultSeconds = absoluteMaxSeconds();
  await Promise.all(sessions.map((s) => {
    const current = String(s._id) === currentSessionId;
    const start = current ? now : s.createdAt.getTime();
    const absoluteAt = policy.absoluteSeconds === null ? null : new Date(start + policy.absoluteSeconds * 1000);
    // Without an account limit, sessions keep Identity's default from sign-in.
    const cap = absoluteAt ?? new Date(s.createdAt.getTime() + defaultSeconds * 1000);
    const expiresAt = current && absoluteAt ? absoluteAt : new Date(Math.min(s.expiresAt.getTime(), cap.getTime()));
    return Session.updateOne({ _id: s._id }, { $set: { idleTimeoutSeconds: policy.idleSeconds, absoluteExpiresAt: absoluteAt, expiresAt, ...(current ? { lastActivityAt: new Date(now) } : {}) } });
  }));
  return policy;
}
