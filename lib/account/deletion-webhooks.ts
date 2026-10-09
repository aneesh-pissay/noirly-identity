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

export function parseDeletionWebhooks(raw: string | undefined, production: boolean): DeletionWebhook[] {
  if (!raw?.trim()) return [];
  const hooks: DeletionWebhook[] = [];
  for (const entry of raw.split(/[\s,]+/)) {
    if (!entry) continue;
    const at = entry.indexOf("=");
    const clientId = entry.slice(0, at).trim();
    const url = entry.slice(at + 1).trim();
    if (at <= 0 || !clientId || !url) {
      throw new Error(`ACCOUNT_DELETION_WEBHOOKS: expected clientId=url, got "${entry}"`);
    }
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new Error(`ACCOUNT_DELETION_WEBHOOKS: invalid URL for ${clientId}`);
    }
    if (parsed.protocol !== "https:" && (production || parsed.protocol !== "http:")) {
      throw new Error(`ACCOUNT_DELETION_WEBHOOKS: ${clientId} must use https`);
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

async function deliver(hook: DeletionWebhook, sub: string): Promise<string | null> {
  try {
    const response = await fetch(hook.url, {
      method: "POST",
      headers: { "content-type": "application/secevent+jwt", accept: "application/json" },
      body: await signDeletionEvent(sub, hook.clientId),
      signal: AbortSignal.timeout(DELIVERY_TIMEOUT_MS),
      cache: "no-store",
    });
    return response.ok ? null : `HTTP ${response.status}`;
  } catch (error) {
    return error instanceof Error ? error.message : "delivery failed";
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
  } catch (error) {
    console.error("Account deletion webhooks misconfigured", error instanceof Error ? error.message : error);
  }
  const results = await Promise.all(hooks.map(async (hook) => ({ hook, error: await deliver(hook, sub) })));
  const pending = results.filter((r) => r.error !== null);
  if (pending.length > 0) {
    await DeletedAccount.updateOne(
      { sub },
      {
        $set: {
          deletedAt: new Date(),
          pending: pending.map((r) => ({ clientId: r.hook.clientId, attempts: 1, lastError: r.error })),
        },
      },
      { upsert: true },
    );
  }
  return {
    delivered: results.filter((r) => r.error === null).map((r) => r.hook.clientId),
    pending: pending.map((r) => r.hook.clientId),
  };
}

/** Re-sends notices that failed earlier. Returns how many are still pending. */
export async function retryPendingDeletionNotices(maxAttempts = 20): Promise<number> {
  const hooks = new Map(configuredWebhooks().map((h) => [h.clientId, h]));
  let stillPending = 0;
  for (const record of await DeletedAccount.find({ "pending.0": { $exists: true } })) {
    const next: DeletedAccountDocument["pending"] = [];
    for (const item of record.pending) {
      const hook = hooks.get(item.clientId);
      // An app removed from the config no longer wants notices.
      if (!hook) continue;
      const error = await deliver(hook, record.sub);
      if (error !== null && item.attempts + 1 < maxAttempts) {
        next.push({ clientId: item.clientId, attempts: item.attempts + 1, lastError: error });
      }
    }
    stillPending += next.length;
    if (next.length === 0) await DeletedAccount.deleteOne({ _id: record._id });
    else await DeletedAccount.updateOne({ _id: record._id }, { $set: { pending: next } });
  }
  return stillPending;
}
