import { Types } from "mongoose";
import { getEnv } from "@/lib/config/env";
import { generateSecureToken, hashToken } from "@/lib/security/crypto";
import { Session, type SessionDocument } from "@/models/Session";
import type { SignInMethod } from "@/lib/audit/chain";
import { isIdle, sessionPolicyFor } from "@/lib/sessions/lifetime";
import { notifySessionsEnded, type EndedSession } from "@/lib/oidc/backchannel-logout";
import { sessionSid } from "@/lib/oidc/sid";
import { afterResponse } from "@/lib/api/after";
import { noteSignIn } from "@/lib/security/risk";
import { AccessToken } from "@/models/AccessToken";
import { RefreshToken } from "@/models/RefreshToken";

export type CreateSessionInput = {
  userId: Types.ObjectId | string;
  ipAddress?: string | null;
  userAgent?: string | null;
  place?: string | null;
  /** The device signing in (lib/security/device.ts), for unusual sign-in detection. */
  deviceId?: string | null;
  ttlSeconds?: number;
  securityVerified?: boolean;
  /** How the person signed in (lib/auth/acr.ts). */
  methods?: SignInMethod[];
};

/** Lean session fields callers need after validation. */
export type ValidatedSession = {
  _id: Types.ObjectId;
  userId: Types.ObjectId;
  expiresAt: Date;
  createdAt: Date;
  lastActivityAt: Date;
  revokedAt: Date | null;
  methods: string[];
  /** When the person last proved who they are: the session's start, or a later step-up. */
  authenticatedAt: Date;
};

export type SessionContext = {
  session: ValidatedSession;
  userId: string;
};

const ACTIVITY_THROTTLE_MS = 5 * 60 * 1000;

export async function createSession(
  input: CreateSessionInput,
): Promise<{ token: string; session: SessionDocument }> {
  const env = getEnv();
  // A domain whose organization requires single sign-on signs in only through its IdP (lib/federation/enforcement.ts).
  if (input.methods?.length) {
    const { assertSsoAllowed } = await import("@/lib/federation/enforcement");
    await assertSsoAllowed(String(input.userId), input.methods, input);
  }
  const token = generateSecureToken(32);
  const policy = await sessionPolicyFor(input.userId);
  const ttl = Math.min(input.ttlSeconds ?? env.SESSION_TTL_SECONDS, policy.absoluteSeconds ?? Infinity);
  const expiresAt = new Date(Date.now() + ttl * 1000);

  const _id = new Types.ObjectId();
  const session = await Session.create({
    _id,
    sid: sessionSid(_id),
    userId: input.userId,
    securityVerifiedAt: input.securityVerified ? new Date() : null,
    tokenHash: hashToken(token),
    expiresAt,
    lastActivityAt: new Date(),
    ipAddress: input.ipAddress ?? null,
    userAgent: input.userAgent ?? null,
    place: input.place ?? null,
    methods: input.methods ?? [],
    idleTimeoutSeconds: policy.idleSeconds,
    absoluteExpiresAt: policy.absoluteSeconds === null ? null : expiresAt,
  });

  // A sign-in (a session made by signing in, with methods): compare it with the account's history.
  if (input.methods?.length) {
    const context = { deviceId: input.deviceId ?? null, userAgent: input.userAgent ?? null, place: input.place ?? null };
    afterResponse(() => noteSignIn(input.userId, context));
  }

  return { token, session };
}

/**
 * Validate a session token without blocking on a write.
 * Activity is updated at most every 5 minutes, fire-and-forget.
 */
export async function validateSession(
  token: string | null | undefined,
): Promise<SessionContext | null> {
  if (!token) {
    return null;
  }

  const session = await Session.findOne({ tokenHash: hashToken(token) }).lean();
  if (!session) {
    return null;
  }

  if (session.revokedAt) {
    return null;
  }

  if (session.expiresAt.getTime() <= Date.now()) {
    return null;
  }

  // Left unused past the account's idle limit: it's over.
  if (isIdle(session)) {
    return null;
  }

  const lastActivity = session.lastActivityAt
    ? new Date(session.lastActivityAt).getTime()
    : 0;
  // Record activity often enough that a short idle limit isn't hit early.
  const throttle = session.idleTimeoutSeconds
    ? Math.min(ACTIVITY_THROTTLE_MS, (session.idleTimeoutSeconds * 1000) / 6)
    : ACTIVITY_THROTTLE_MS;
  if (Date.now() - lastActivity > throttle) {
    void Session.updateOne(
      { _id: session._id },
      { $set: { lastActivityAt: new Date() } },
    ).exec();
  }

  return {
    session: {
      _id: session._id,
      userId: session.userId,
      expiresAt: session.expiresAt,
      createdAt: session.createdAt,
      lastActivityAt: session.lastActivityAt,
      revokedAt: session.revokedAt ?? null,
      methods: session.methods ?? [],
      authenticatedAt: session.authenticatedAt ?? session.createdAt,
    },
    userId: String(session.userId),
  };
}

export async function refreshSessionExpiry(
  sessionId: Types.ObjectId | string,
  ttlSeconds?: number,
): Promise<SessionDocument | null> {
  const ttl = ttlSeconds ?? getEnv().SESSION_TTL_SECONDS;
  const existing = await Session.findById(sessionId).select("absoluteExpiresAt").lean();
  // Never past the account's absolute limit.
  const until = Math.min(Date.now() + ttl * 1000, existing?.absoluteExpiresAt?.getTime() ?? Infinity);
  return Session.findByIdAndUpdate(
    sessionId,
    {
      expiresAt: new Date(until),
      lastActivityAt: new Date(),
    },
    { returnDocument: "after" },
  );
}

/**
 * Ends the live sessions matching `filter`, then tells the apps they reached
 * (back-channel logout). Every sign-out goes through here.
 */
async function endSessions(filter: Record<string, unknown>) {
  // Already-expired sessions are over; apps were told nothing then and needn't be now.
  const sessions = await Session.find({ ...filter, revokedAt: null, expiresAt: { $gt: new Date() } }).select("_id userId appIds").lean();
  if (sessions.length === 0) return { sessions: [] as EndedSession[], backchannel: { delivered: [], failed: [] } };
  const ids = sessions.map((s) => s._id);
  const now = new Date();
  await Session.updateMany({ _id: { $in: ids }, revokedAt: null }, { $set: { revokedAt: now } });
  // Its tokens go with it: refresh tokens can't outlive the session they came from.
  await Promise.all([
    AccessToken.updateMany({ sessionId: { $in: ids }, revokedAt: null }, { $set: { revokedAt: now } }),
    RefreshToken.updateMany({ sessionId: { $in: ids }, revokedAt: null }, { $set: { revokedAt: now } }),
  ]);
  return { sessions: sessions as EndedSession[], backchannel: await notifySessionsEnded(sessions) };
}

export async function revokeSession(
  sessionId: Types.ObjectId | string,
): Promise<void> {
  await endSessions({ _id: sessionId });
}

/** Ends one session; says which apps it reached and which didn't take the back-channel logout. */
export async function revokeSessionByToken(token: string) {
  const { sessions, backchannel } = await endSessions({ tokenHash: hashToken(token) });
  return { session: sessions[0] ?? null, backchannelFailed: backchannel.failed };
}

export async function revokeAllUserSessions(
  userId: Types.ObjectId | string,
  exceptSessionId?: Types.ObjectId | string,
): Promise<number> {
  const filter: Record<string, unknown> = {
    userId,
    revokedAt: null,
  };
  if (exceptSessionId) {
    filter._id = { $ne: exceptSessionId };
  }
  const { sessions } = await endSessions(filter);
  return sessions.length;
}
