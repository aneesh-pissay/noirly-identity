import { randomUUID } from "node:crypto";
import { SignJWT } from "jose";
import { getEnv } from "@/lib/config/env";
import { getSigningKeys } from "@/lib/oidc/keys";
import { sessionSid } from "@/lib/oidc/sid";
import { LogoutNotice } from "@/models/LogoutNotice";
import { OAuthClient } from "@/models/OAuthClient";

/**
 * OpenID Connect Back-Channel Logout 1.0. When an Identity session ends,
 * every app it signed in to that has a `backchannelLogoutUri` gets a logout
 * token POSTed to it (form field `logout_token`), so it can end its own
 * session for that person at once. Apps without one, or whose delivery
 * failed, are signed out by front-channel when the person signs out in this
 * browser (`frontchannelLogoutUrls`).
 */

export const BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";

const DELIVERY_TIMEOUT_MS = 3000;
const MAX_ATTEMPTS = 10;

/** A session that just ended: whose, which, and the apps it reached. */
export type EndedSession = { _id: unknown; userId: unknown; appIds?: string[] | null };

type Notice = { clientId: string; sub: string; sid: string | null };

/** A logout token for one app: `sid` for one session, or none for every session of `sub`. */
export async function signLogoutToken(input: Notice): Promise<string> {
  const env = getEnv();
  const keys = await getSigningKeys();
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ events: { [BACKCHANNEL_LOGOUT_EVENT]: {} }, ...(input.sid ? { sid: input.sid } : {}) })
    .setProtectedHeader({ alg: "RS256", kid: keys.kid, typ: "logout+jwt" })
    .setIssuer(env.OIDC_ISSUER)
    .setSubject(input.sub)
    .setAudience(input.clientId)
    .setIssuedAt(now)
    .setExpirationTime(now + 2 * 60)
    .setJti(randomUUID())
    .sign(keys.privateKey);
}

async function deliver(url: string, notice: Notice): Promise<string | null> {
  try {
    const response = await fetch(url, {
      method: "POST",
      redirect: "error",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: new URLSearchParams({ logout_token: await signLogoutToken(notice) }).toString(),
      signal: AbortSignal.timeout(DELIVERY_TIMEOUT_MS),
      cache: "no-store",
    });
    return response.ok ? null : `HTTP ${response.status}`;
  } catch {
    return "delivery failed";
  }
}

async function backchannelUris(clientIds: string[]) {
  if (clientIds.length === 0) return new Map<string, string>();
  const clients = await OAuthClient.find({ clientId: { $in: clientIds }, status: "active", backchannelLogoutUri: { $nin: [null, ""] } })
    .select("clientId backchannelLogoutUri")
    .lean();
  return new Map(clients.map((c) => [c.clientId, c.backchannelLogoutUri as string]));
}

/**
 * Tells the apps these sessions reached that they've ended (or only
 * `onlyClientId`). With `everyAppSession` each app gets one token without
 * `sid`: every session of that person there. Never throws, since the sessions
 * are already over; failures are kept for `retryPendingLogoutNotices`.
 */
export async function notifySessionsEnded(
  sessions: EndedSession[],
  options: { onlyClientId?: string; everyAppSession?: boolean } = {},
): Promise<{ delivered: string[]; failed: string[] }> {
  try {
    const wanted = new Map<string, Notice>();
    for (const session of sessions) {
      const sub = String(session.userId);
      const sid = options.everyAppSession ? null : sessionSid(session._id);
      for (const clientId of session.appIds ?? []) {
        if (options.onlyClientId && clientId !== options.onlyClientId) continue;
        wanted.set(`${clientId}|${sub}|${sid}`, { clientId, sub, sid });
      }
    }
    const notices = [...wanted.values()];
    const uris = await backchannelUris([...new Set(notices.map((n) => n.clientId))]);
    const results = await Promise.all(
      notices.filter((n) => uris.has(n.clientId)).map(async (notice) => ({ notice, error: await deliver(uris.get(notice.clientId)!, notice) })),
    );
    const failed = results.filter((r) => r.error !== null);
    if (failed.length) {
      await LogoutNotice.insertMany(failed.map((r) => ({ ...r.notice, lastError: r.error })));
    }
    return {
      delivered: [...new Set(results.filter((r) => r.error === null).map((r) => r.notice.clientId))],
      failed: [...new Set(failed.map((r) => r.notice.clientId))],
    };
  } catch (error) {
    console.error("Back-channel logout failed", error instanceof Error ? error.message : "unknown error");
    return { delivered: [], failed: [] };
  }
}

/** Re-sends logouts apps didn't take. Returns how many are still pending. */
export async function retryPendingLogoutNotices(): Promise<number> {
  const pending = await LogoutNotice.find({}).sort({ createdAt: 1 }).limit(500);
  const uris = await backchannelUris([...new Set(pending.map((n) => n.clientId))]);
  let still = 0;
  for (const notice of pending) {
    const url = uris.get(notice.clientId);
    // The app no longer takes back-channel logouts, or is gone.
    if (!url) {
      await LogoutNotice.deleteOne({ _id: notice._id });
      continue;
    }
    const error = await deliver(url, notice);
    if (error === null || notice.attempts + 1 >= MAX_ATTEMPTS) {
      await LogoutNotice.deleteOne({ _id: notice._id });
    } else {
      await LogoutNotice.updateOne({ _id: notice._id }, { $inc: { attempts: 1 }, $set: { lastError: error } });
      still += 1;
    }
  }
  return still;
}

/**
 * Front-channel logout (OpenID Connect Front-Channel Logout 1.0) for a
 * session signed out in this browser: URLs to load in hidden frames, for the
 * apps it reached that have no back-channel, or whose back-channel failed.
 */
export async function frontchannelLogoutUrls(session: EndedSession, backchannelFailed: string[] = []): Promise<string[]> {
  const appIds = session.appIds ?? [];
  if (appIds.length === 0) return [];
  const clients = await OAuthClient.find({ clientId: { $in: appIds }, status: "active", frontchannelLogoutUri: { $nin: [null, ""] } })
    .select("clientId frontchannelLogoutUri backchannelLogoutUri")
    .lean();
  const issuer = getEnv().OIDC_ISSUER;
  const sid = sessionSid(session._id);
  return clients
    .filter((c) => !c.backchannelLogoutUri || backchannelFailed.includes(c.clientId))
    .map((c) => {
      const url = new URL(c.frontchannelLogoutUri as string);
      url.searchParams.set("iss", issuer);
      url.searchParams.set("sid", sid);
      return url.toString();
    });
}
