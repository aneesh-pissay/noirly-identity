import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { deviceLabel, describeActivity } from "@/lib/audit/activity";
import { notifySessionsEnded } from "@/lib/oidc/backchannel-logout";
import { recordEvent, type RequestMeta } from "@/lib/audit/event-log";
import { AccessToken } from "@/models/AccessToken";
import { OAuthClient } from "@/models/OAuthClient";
import { RefreshToken } from "@/models/RefreshToken";
import { Session } from "@/models/Session";

/**
 * Every browser and device signed in to an account, for its owner to see
 * and sign out of: one, several, or all but this one. Signing a session out
 * also ends the app sign-ins made through it.
 */

export type DeviceSession = {
  id: string;
  device: string;
  ipAddress: string | null;
  place: string | null;
  signedInAt: string;
  lastActiveAt: string;
  /** "Signed in with password and an authenticator code". */
  how: string | null;
  current: boolean;
  /** Apps this session signed in to, and whether they still are. */
  apps: Array<{ clientId: string; name: string; signedIn: boolean }>;
};

function oid(id: string, what = "session") {
  if (!Types.ObjectId.isValid(id)) throw new AppError(`Invalid ${what}`, 400, "invalid_request");
  return new Types.ObjectId(id);
}

const liveFilter = (userId: Types.ObjectId) => ({ userId, revokedAt: null, expiresAt: { $gt: new Date() } });

export async function listDeviceSessions(userId: string, currentSessionId: string): Promise<DeviceSession[]> {
  const id = oid(userId, "account");
  const sessions = await Session.find(liveFilter(id)).sort({ lastActivityAt: -1 }).limit(100).lean();
  const sessionIds = sessions.map((s) => s._id);
  const now = new Date();
  const working = { sessionId: { $in: sessionIds }, revokedAt: null, expiresAt: { $gt: now } };
  const [access, refresh] = await Promise.all([
    AccessToken.find(working).select("sessionId clientId").lean(),
    RefreshToken.find(working).select("sessionId clientId").lean(),
  ]);
  const clientIds = [...new Set([...access, ...refresh].map((t) => t.clientId).concat(sessions.flatMap((s) => s.appIds ?? [])))];
  const names = new Map((await OAuthClient.find({ clientId: { $in: clientIds } }).select("clientId name").lean()).map((c) => [c.clientId, c.name]));
  const liveApps = new Map<string, Set<string>>();
  for (const token of [...access, ...refresh]) {
    const key = String(token.sessionId);
    if (!liveApps.has(key)) liveApps.set(key, new Set());
    liveApps.get(key)!.add(token.clientId);
  }
  const appsOf = (session: { _id: Types.ObjectId; appIds?: string[] | null }) => {
    const live = liveApps.get(String(session._id)) ?? new Set<string>();
    return [...new Set([...(session.appIds ?? []), ...live])]
      .map((clientId) => ({ clientId, name: names.get(clientId) ?? clientId, signedIn: live.has(clientId) }))
      .sort((a, b) => Number(b.signedIn) - Number(a.signedIn) || a.name.localeCompare(b.name));
  };
  // The current session first, then the most recently active.
  const rows = sessions.map((s): DeviceSession => ({
    id: String(s._id),
    device: deviceLabel(s.userAgent),
    ipAddress: s.ipAddress ?? null,
    place: s.place ?? null,
    signedInAt: (s.authenticatedAt ?? s.createdAt).toISOString(),
    lastActiveAt: (s.lastActivityAt ?? s.createdAt).toISOString(),
    how: s.methods?.length ? describeActivity("auth.signed_in", { methods: s.methods }) : null,
    current: String(s._id) === currentSessionId,
    apps: appsOf(s),
  }));
  return [...rows.filter((r) => r.current), ...rows.filter((r) => !r.current)];
}

/** Ends sessions, and the app sign-ins made through them. Returns how many ended, and whether this one did. */
async function endSessions(userId: Types.ObjectId, sessionIds: Types.ObjectId[], currentSessionId: string, meta: RequestMeta) {
  if (!sessionIds.length) return { count: 0, includingThisOne: false };
  const now = new Date();
  const ended = await Session.find({ ...liveFilter(userId), _id: { $in: sessionIds } }).select("_id userId appIds").lean();
  const ids = ended.map((s) => s._id);
  await Session.updateMany({ _id: { $in: ids } }, { $set: { revokedAt: now } });
  await AccessToken.updateMany({ sessionId: { $in: ids }, revokedAt: null }, { $set: { revokedAt: now } });
  await RefreshToken.updateMany({ sessionId: { $in: ids }, revokedAt: null }, { $set: { revokedAt: now } });
  await notifySessionsEnded(ended);
  const includingThisOne = ids.some((s) => String(s) === currentSessionId);
  if (ids.length) await recordEvent({ action: "auth.sessions_signed_out", subjectId: userId, request: meta, data: { count: ids.length, includingThisOne } });
  return { count: ids.length, includingThisOne };
}

/** Signs out the chosen sessions (this one too, if chosen). Ones that aren't this account's are ignored. */
export async function signOutSessions(userId: string, ids: string[], currentSessionId: string, meta: RequestMeta = {}) {
  return endSessions(oid(userId, "account"), ids.map((id) => oid(id)), currentSessionId, meta);
}

/**
 * Signs one app out, on one device (`sessionId`) or every device, leaving
 * Identity and other apps signed in: its tokens stop working at once.
 * Returns how many sign-ins ended.
 */
export async function signOutOfApp(userId: string, clientId: string, sessionId: string | null, meta: RequestMeta = {}) {
  const id = oid(userId, "account");
  const filter: Record<string, unknown> = { userId: id, clientId, revokedAt: null };
  if (sessionId) {
    // Only a session of this account.
    if (!(await Session.exists({ _id: oid(sessionId), userId: id }))) throw new AppError("Session not found", 404, "not_found");
    filter.sessionId = oid(sessionId);
  }
  const now = new Date();
  const [access, refresh] = await Promise.all([
    AccessToken.updateMany(filter, { $set: { revokedAt: now } }),
    RefreshToken.updateMany(filter, { $set: { revokedAt: now } }),
  ]);
  const ended = access.modifiedCount + refresh.modifiedCount;
  // The app ends its own session too: this one (by sid), or every one of yours there.
  if (ended) await notifySessionsEnded([{ _id: sessionId, userId: id, appIds: [clientId] }], { onlyClientId: clientId, everyAppSession: !sessionId });
  if (ended) await recordEvent({ action: "auth.app_signed_out", subjectId: id, clientId, request: meta, data: { everywhere: !sessionId } });
  return { ended };
}

/** Signs out everywhere but here. */
export async function signOutOtherSessions(userId: string, currentSessionId: string, meta: RequestMeta = {}) {
  const id = oid(userId, "account");
  const others = await Session.find({ ...liveFilter(id), _id: { $ne: oid(currentSessionId) } }).select("_id").lean();
  return endSessions(id, others.map((s) => s._id), currentSessionId, meta);
}
