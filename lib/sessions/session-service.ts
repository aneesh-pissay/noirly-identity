import type { Types } from "mongoose";
import { getEnv } from "@/lib/config/env";
import { generateSecureToken, hashToken } from "@/lib/security/crypto";
import { Session, type SessionDocument } from "@/models/Session";

export type CreateSessionInput = {
  userId: Types.ObjectId | string;
  ipAddress?: string | null;
  userAgent?: string | null;
  ttlSeconds?: number;
  securityVerified?: boolean;
};

/** Lean session fields callers need after validation. */
export type ValidatedSession = {
  _id: Types.ObjectId;
  userId: Types.ObjectId;
  expiresAt: Date;
  createdAt: Date;
  lastActivityAt: Date;
  revokedAt: Date | null;
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
  const token = generateSecureToken(32);
  const ttl = input.ttlSeconds ?? env.SESSION_TTL_SECONDS;
  const expiresAt = new Date(Date.now() + ttl * 1000);

  const session = await Session.create({
    userId: input.userId,
    securityVerifiedAt: input.securityVerified ? new Date() : null,
    tokenHash: hashToken(token),
    expiresAt,
    lastActivityAt: new Date(),
    ipAddress: input.ipAddress ?? null,
    userAgent: input.userAgent ?? null,
  });

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

  const lastActivity = session.lastActivityAt
    ? new Date(session.lastActivityAt).getTime()
    : 0;
  if (Date.now() - lastActivity > ACTIVITY_THROTTLE_MS) {
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
    },
    userId: String(session.userId),
  };
}

export async function refreshSessionExpiry(
  sessionId: Types.ObjectId | string,
  ttlSeconds?: number,
): Promise<SessionDocument | null> {
  const ttl = ttlSeconds ?? getEnv().SESSION_TTL_SECONDS;
  return Session.findByIdAndUpdate(
    sessionId,
    {
      expiresAt: new Date(Date.now() + ttl * 1000),
      lastActivityAt: new Date(),
    },
    { returnDocument: "after" },
  );
}

export async function revokeSession(
  sessionId: Types.ObjectId | string,
): Promise<void> {
  await Session.findByIdAndUpdate(sessionId, { revokedAt: new Date() });
}

export async function revokeSessionByToken(token: string): Promise<void> {
  await Session.findOneAndUpdate(
    { tokenHash: hashToken(token) },
    { revokedAt: new Date() },
  );
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
  const result = await Session.updateMany(filter, { revokedAt: new Date() });
  return result.modifiedCount;
}
