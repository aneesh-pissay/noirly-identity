import { randomUUID } from "node:crypto";
import { SignJWT } from "jose";
import { getEnv } from "@/lib/config/env";
import { getSigningKeys } from "@/lib/oidc/keys";
import { DeletedAccount, type DeletedAccountDocument } from "@/models/DeletedAccount";

/**
 * Tells product apps (Flow, Ledger, …) that an account is gone so they delete
 * their own data for it.
 *
 * Targets come from `ACCOUNT_DELETION_WEBHOOKS`: `clientId=url` pairs, comma or
 * newline separated. Each notice is a Security Event Token (RFC 8417): a JWT
 * signed with Identity's OIDC key (verify it with `/.well-known/jwks.json`),
 * `aud` = the app's client id, `sub` = the deleted user, POSTed as
 * `application/secevent+jwt`. Any 2xx counts as delivered.
 */

export const ACCOUNT_DELETED_EVENT = "https://noirly.dev/events/account-deleted";

const DELIVERY_TIMEOUT_MS = 8000;

export type DeletionWebhook = { clientId: string; url: string };

/** `clientId=url` pairs, comma or newline separated; `setting` names the variable in errors. */
export function parseDeletionWebhooks(raw: string | undefined, production: boolean, setting = "ACCOUNT_DELETION_WEBHOOKS"): DeletionWebhook[] {
  if (!raw?.trim()) return [];
  const hooks: DeletionWebhook[] = [];
  for (const entry of raw.split(/[\s,]+/)) {
    if (!entry) continue;
    const at = entry.indexOf("=");
    const clientId = entry.slice(0, at).trim();
    const url = entry.slice(at + 1).trim();
    if (at <= 0 || !clientId || !url) {
      throw new Error(`${setting}: expected clientId=url, got "${entry}"`);
    }
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new Error(`${setting}: invalid URL for ${clientId}`);
    }
    if (parsed.protocol !== "https:" && (production || parsed.protocol !== "http:")) {
      throw new Error(`${setting}: ${clientId} must use https`);
    }
    hooks.push({ clientId, url: parsed.toString() });
  }
  return hooks;
}

function configuredWebhooks(): DeletionWebhook[] {
  const env = getEnv();
  return parseDeletionWebhooks(env.ACCOUNT_DELETION_WEBHOOKS, env.NODE_ENV === "production");
}

export async function signDeletionEvent(sub: string, clientId: string): Promise<string> {
  const env = getEnv();
  const keys = await getSigningKeys();
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ events: { [ACCOUNT_DELETED_EVENT]: {} } })
    .setProtectedHeader({ alg: "RS256", kid: keys.kid, typ: "secevent+jwt" })
    .setIssuer(env.OIDC_ISSUER)
    .setSubject(sub)
    .setAudience(clientId)
    .setIssuedAt(now)
    .setExpirationTime(now + 15 * 60)
    .setJti(randomUUID())
    .sign(keys.privateKey);
}

export const DELETION_RECORD_DAYS = 90;
const keepUntil = () => new Date(Date.now() + DELETION_RECORD_DAYS * 86_400_000);

async function deliver(hook: DeletionWebhook, sub: string): Promise<string | null> {
  try {
    const response = await fetch(hook.url, {
      method: "POST",
      redirect: "error",
      headers: { "content-type": "application/secevent+jwt", accept: "application/json" },
      body: await signDeletionEvent(sub, hook.clientId),
      signal: AbortSignal.timeout(DELIVERY_TIMEOUT_MS),
      cache: "no-store",
    });
    return response.ok ? null : `HTTP ${response.status}`;
  } catch (error) {
    void error;
    return "delivery failed";
  }
}

/**
 * Records the tombstone and notifies every configured app. Apps that fail stay
 * pending for `retryPendingDeletionNotices`. Never throws: the account is
 * already deleted by the time this runs.
 */
export async function notifyAccountDeleted(sub: string): Promise<{ delivered: string[]; pending: string[] }> {
  let hooks: DeletionWebhook[] = [];
  try {
    hooks = configuredWebhooks();
  } catch {
    console.error("Account deletion webhooks misconfigured");
  }
  const results = await Promise.all(hooks.map(async (hook) => ({ hook, error: await deliver(hook, sub) })));
  const pending = results.filter((r) => r.error !== null);
  const now = new Date();
  await DeletedAccount.updateOne(
    { sub },
    {
      $set: {
        deletedAt: now,
        keepUntil: keepUntil(),
        pending: pending.map((r) => ({ clientId: r.hook.clientId, attempts: 1, lastError: r.error })),
        delivered: results.filter((r) => r.error === null).map((r) => ({ clientId: r.hook.clientId, at: now })),
        failed: [],
      },
    },
    { upsert: true },
  ).catch(() => undefined);
  return {
    delivered: results.filter((r) => r.error === null).map((r) => r.hook.clientId),
    pending: pending.map((r) => r.hook.clientId),
  };
}

/** Retries one tombstone's pending notices (and, with `includeFailed`, the ones given up on): how many still wait, and which apps gave up just now. */
export async function retryDeletionRecord(record: DeletedAccountDocument, maxAttempts = 20, includeFailed = false): Promise<{ pending: number; gaveUp: string[] }> {
  const gaveUp: string[] = [];
  const hooks = new Map(configuredWebhooks().map((h) => [h.clientId, h]));
  const next: DeletedAccountDocument["pending"] = [];
  const failed: DeletedAccountDocument["failed"] = includeFailed ? [] : [...(record.failed ?? [])];
  const delivered = [...(record.delivered ?? [])];
  const items = [...record.pending, ...(includeFailed ? (record.failed ?? []).map((f) => ({ ...f, attempts: 0 })) : [])];
  for (const item of items) {
    const hook = hooks.get(item.clientId);
    // An app removed from the config no longer wants notices.
    if (!hook) continue;
    const error = await deliver(hook, record.sub);
    if (error === null) delivered.push({ clientId: item.clientId, at: new Date() });
    else if (item.attempts + 1 < maxAttempts) next.push({ clientId: item.clientId, attempts: item.attempts + 1, lastError: error });
    else {
      failed.push({ clientId: item.clientId, attempts: item.attempts + 1, lastError: error });
      gaveUp.push(item.clientId);
    }
  }
  await DeletedAccount.updateOne({ _id: record._id }, { $set: { pending: next, delivered, failed } });
  return { pending: next.length, gaveUp };
}

/** Re-sends notices that failed earlier. Returns how many are still pending. */
export async function retryPendingDeletionNotices(maxAttempts = 20): Promise<number> {
  let stillPending = 0;
  const gaveUp = new Map<string, number>();
  for (const record of await DeletedAccount.find({ "pending.0": { $exists: true } }).lean<DeletedAccountDocument[]>()) {
    const result = await retryDeletionRecord(record, maxAttempts);
    stillPending += result.pending;
    for (const clientId of result.gaveUp) gaveUp.set(clientId, (gaveUp.get(clientId) ?? 0) + 1);
  }
  // One email per run, however many accounts, so an app that's down for good doesn't flood admins.
  if (gaveUp.size) {
    const { noticeToAdmins } = await import("@/lib/notifications/notices");
    await noticeToAdmins({
      kind: "deletion-gave-up",
      subject: "Apps never confirmed account deletions",
      paragraphs: [
        `After every retry, these apps still haven't confirmed deleting accounts' data: ${[...gaveUp].map(([app, n]) => `${app} (${n} account${n === 1 ? "" : "s"})`).join(", ")}.`,
        "Their data for those accounts may still exist. Check each app's deletion endpoint, then use Retry now on the deletions page.",
      ],
      action: { label: "Open account deletions", path: "/admin/deletions" },
    });
  }
  return stillPending;
}
