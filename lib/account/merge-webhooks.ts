import { randomUUID } from "node:crypto";
import { SignJWT } from "jose";
import { parseDeletionWebhooks, type DeletionWebhook } from "@/lib/account/deletion-webhooks";
import { getEnv } from "@/lib/config/env";
import { getSigningKeys } from "@/lib/oidc/keys";
import { MergedAccount, type MergedAccountDocument } from "@/models/MergedAccount";

/**
 * Tells product apps that one account was merged into another, so they move
 * what they hold for the old `sub` to the new one.
 *
 * Targets come from `ACCOUNT_MERGE_WEBHOOKS` (`clientId=url` pairs), apart
 * from the deletion webhooks so an app takes these only once it handles
 * them. Each notice is a Security Event Token (RFC 8417) like the deletion
 * notice: signed with Identity's OIDC key, `aud` = the app's client id,
 * `sub` = the old (merged-away) account, and the event carries `new_sub`.
 */

export const ACCOUNT_MERGED_EVENT = "https://noirly.dev/events/account-merged";

const DELIVERY_TIMEOUT_MS = 8000;

function configuredWebhooks(): DeletionWebhook[] {
  const env = getEnv();
  return parseDeletionWebhooks(env.ACCOUNT_MERGE_WEBHOOKS, env.NODE_ENV === "production", "ACCOUNT_MERGE_WEBHOOKS");
}

export async function signMergeEvent(fromSub: string, toSub: string, clientId: string): Promise<string> {
  const env = getEnv();
  const keys = await getSigningKeys();
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ events: { [ACCOUNT_MERGED_EVENT]: { new_sub: toSub } } })
    .setProtectedHeader({ alg: "RS256", kid: keys.kid, typ: "secevent+jwt" })
    .setIssuer(env.OIDC_ISSUER)
    .setSubject(fromSub)
    .setAudience(clientId)
    .setIssuedAt(now)
    .setExpirationTime(now + 15 * 60)
    .setJti(randomUUID())
    .sign(keys.privateKey);
}

async function deliver(hook: DeletionWebhook, fromSub: string, toSub: string): Promise<string | null> {
  try {
    const response = await fetch(hook.url, {
      method: "POST",
      redirect: "error",
      headers: { "content-type": "application/secevent+jwt", accept: "application/json" },
      body: await signMergeEvent(fromSub, toSub, hook.clientId),
      signal: AbortSignal.timeout(DELIVERY_TIMEOUT_MS),
      cache: "no-store",
    });
    return response.ok ? null : `HTTP ${response.status}`;
  } catch {
    return "delivery failed";
  }
}

/**
 * Records where the old `sub` went (kept for good) and notifies every
 * configured app; ones that fail stay pending for `retryPendingMergeNotices`.
 * Never throws: the merge has already happened.
 */
export async function notifyAccountMerged(fromSub: string, toSub: string): Promise<{ delivered: string[]; pending: string[] }> {
  let hooks: DeletionWebhook[] = [];
  try {
    hooks = configuredWebhooks();
  } catch {
    console.error("Account merge webhooks misconfigured");
  }
  const results = await Promise.all(hooks.map(async (hook) => ({ hook, error: await deliver(hook, fromSub, toSub) })));
  const pending = results.filter((r) => r.error !== null);
  await MergedAccount.updateOne(
    { fromSub },
    { $set: { toSub, mergedAt: new Date(), pending: pending.map((r) => ({ clientId: r.hook.clientId, attempts: 1, lastError: r.error })) } },
    { upsert: true },
  );
  // An account merged into this one earlier now lands here too.
  await MergedAccount.updateMany({ toSub: fromSub }, { $set: { toSub } });
  return { delivered: results.filter((r) => r.error === null).map((r) => r.hook.clientId), pending: pending.map((r) => r.hook.clientId) };
}

/** Re-sends merge notices that failed earlier. Returns how many are still pending. */
export async function retryPendingMergeNotices(maxAttempts = 20): Promise<number> {
  const hooks = new Map(configuredWebhooks().map((h) => [h.clientId, h]));
  let stillPending = 0;
  for (const record of await MergedAccount.find({ "pending.0": { $exists: true } })) {
    const next: MergedAccountDocument["pending"] = [];
    for (const item of record.pending) {
      const hook = hooks.get(item.clientId);
      if (!hook) continue;
      const error = await deliver(hook, record.fromSub, record.toSub);
      if (error !== null && item.attempts + 1 < maxAttempts) next.push({ clientId: item.clientId, attempts: item.attempts + 1, lastError: error });
    }
    stillPending += next.length;
    await MergedAccount.updateOne({ _id: record._id }, { $set: { pending: next } });
  }
  return stillPending;
}

/** The account a subject id belongs to now: itself, or where it was merged. */
export async function currentSubject(sub: string): Promise<string> {
  const merged = await MergedAccount.findOne({ fromSub: sub }).select("toSub").lean();
  return merged?.toSub ?? sub;
}
