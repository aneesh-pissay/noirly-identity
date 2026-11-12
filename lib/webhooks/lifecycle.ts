import { randomUUID } from "node:crypto";
import { SignJWT } from "jose";
import { Schema, Types, model, models, type Model } from "mongoose";
import { getEnv } from "@/lib/config/env";
import { getSigningKeys } from "@/lib/oidc/keys";
import { AppAccess } from "@/models/AppAccess";
import { OAuthClient } from "@/models/OAuthClient";
import { Organization } from "@/models/Organization";

/**
 * Lifecycle webhooks: apps hear when someone they know is created, updated,
 * deactivated, reactivated or deleted, or when a membership changes.
 *
 * An app subscribes by setting `lifecycleWebhookUri` on its client (and,
 * optionally, `lifecycleEvents` to pick events). It gets an event when the
 * person has used it (AppAccess) or, for an organization's event, when the
 * organization lists the app (or lets members use every app).
 *
 * Each delivery is a Security Event Token (RFC 8417) POSTed as
 * `application/secevent+jwt`: signed with Identity's JWKS keys, `aud` = the
 * app, `sub` = the person, `txn` = the delivery id (the same on retries, so
 * apps can drop repeats), and `events` = { "<event URI>": { …details } }.
 * Any 2xx counts. Failures are kept in an outbox and retried with backoff by
 * the scheduled job, up to MAX_ATTEMPTS, for a week.
 *
 * Written so it can move into `@noirly-dev/webhooks` once that package is
 * published: signing, delivery and the outbox don't know about Identity's models.
 */

export const LIFECYCLE_EVENTS = ["user.created", "user.updated", "user.deactivated", "user.reactivated", "user.deleted", "membership.changed"] as const;
export type LifecycleEvent = (typeof LIFECYCLE_EVENTS)[number];
export const eventUri = (event: LifecycleEvent) => `https://noirly.dev/events/${event.replace(".", "-")}`;

const MAX_ATTEMPTS = 10;
const TIMEOUT_MS = 8000;
const KEEP_DAYS = 7;

type DeliveryDoc = {
  _id: Types.ObjectId;
  txn: string;
  clientId: string;
  event: LifecycleEvent;
  sub: string;
  data: Record<string, unknown>;
  attempts: number;
  nextAttemptAt: Date | null;
  deliveredAt: Date | null;
  lastError: string | null;
  expiresAt: Date;
};

const deliverySchema = new Schema<DeliveryDoc>(
  {
    txn: { type: String, required: true, unique: true },
    clientId: { type: String, required: true, index: true },
    event: { type: String, required: true },
    sub: { type: String, required: true },
    data: { type: Schema.Types.Mixed, default: {} },
    attempts: { type: Number, default: 0 },
    nextAttemptAt: { type: Date, default: null, index: true },
    deliveredAt: { type: Date, default: null },
    lastError: { type: String, default: null },
    expiresAt: { type: Date, required: true, index: { expireAfterSeconds: 0 } },
  },
  { timestamps: true, minimize: false },
);
export const WebhookDelivery: Model<DeliveryDoc> = (models.WebhookDelivery as never) || model("WebhookDelivery", deliverySchema, "webhook_deliveries");

export async function signLifecycleEvent(d: Pick<DeliveryDoc, "txn" | "clientId" | "event" | "sub" | "data">): Promise<string> {
  const keys = await getSigningKeys();
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ txn: d.txn, events: { [eventUri(d.event)]: d.data } })
    .setProtectedHeader({ alg: "RS256", kid: keys.kid, typ: "secevent+jwt" })
    .setIssuer(getEnv().OIDC_ISSUER)
    .setSubject(d.sub)
    .setAudience(d.clientId)
    .setIssuedAt(now)
    .setExpirationTime(now + 15 * 60)
    .setJti(randomUUID())
    .sign(keys.privateKey);
}

const backoffMs = (attempts: number) => Math.min(60_000 * 2 ** attempts, 6 * 3600_000);

async function attempt(d: DeliveryDoc, url: string | null): Promise<"delivered" | "pending" | "gave_up"> {
  const attempts = d.attempts + 1;
  let error: string | null = url ? null : "The app no longer takes lifecycle events";
  if (url) {
    try {
      const res = await fetch(url, { method: "POST", redirect: "error", headers: { "content-type": "application/secevent+jwt", accept: "application/json" }, body: await signLifecycleEvent(d), signal: AbortSignal.timeout(TIMEOUT_MS), cache: "no-store" });
      if (!res.ok) error = `HTTP ${res.status}`;
    } catch (e) {
      error = e instanceof Error && e.name === "TimeoutError" ? "timed out" : "delivery failed";
    }
  }
  const done = error === null;
  const giveUp = !done && (attempts >= MAX_ATTEMPTS || !url);
  const outcome = done ? "delivered" : giveUp ? "gave_up" : "pending";
  await WebhookDelivery.updateOne(
    { _id: d._id },
    { $set: { attempts, lastError: error, deliveredAt: done ? new Date() : null, nextAttemptAt: done || giveUp ? null : new Date(Date.now() + backoffMs(attempts)) } },
  );
  return outcome;
}

/** Which subscribed apps hear about this person (and organization). */
async function subscribers(event: LifecycleEvent, userId: string, organizationId?: string | null) {
  const used = await AppAccess.distinct("clientId", { userId: new Types.ObjectId(userId), removedAt: null });
  const filter: Record<string, unknown>[] = [{ clientId: { $in: used } }];
  if (organizationId && Types.ObjectId.isValid(organizationId)) {
    const org = await Organization.findById(new Types.ObjectId(organizationId)).select("appsMode apps").lean();
    if (org?.appsMode === "listed") filter.push({ appKey: { $in: (org.apps ?? []).map((a) => a.appKey) } });
    else if (org) filter.push({});
  }
  const clients = await OAuthClient.find({ $or: filter, lifecycleWebhookUri: { $nin: [null, ""] }, status: "active" }).select("clientId lifecycleWebhookUri lifecycleEvents").lean();
  return clients.filter((c) => {
    const wanted = (c as { lifecycleEvents?: string[] }).lifecycleEvents;
    return !wanted?.length || wanted.includes(event);
  });
}

/**
 * Records and sends one lifecycle event to every app that should hear it.
 * Never throws (the change already happened); failures wait for the retry job.
 */
export async function emitLifecycle(event: LifecycleEvent, input: { userId: string; organizationId?: string | null; data?: Record<string, unknown> }): Promise<number> {
  try {
    const clients = await subscribers(event, input.userId, input.organizationId);
    const data = { ...(input.organizationId ? { organizationId: input.organizationId } : {}), ...input.data };
    const docs = await Promise.all(
      clients.map((c) => WebhookDelivery.create({ txn: randomUUID(), clientId: c.clientId, event, sub: input.userId, data, expiresAt: new Date(Date.now() + KEEP_DAYS * 86_400_000) })),
    );
    const urls = new Map(clients.map((c) => [c.clientId, c.lifecycleWebhookUri as string]));
    await Promise.all(docs.map((d) => attempt(d.toObject() as DeliveryDoc, urls.get(d.clientId) ?? null)));
    return docs.length;
  } catch (error) {
    console.error("Lifecycle webhook failed", error instanceof Error ? error.message : error);
    return 0;
  }
}

/** Retries deliveries that are due (the scheduled job). Returns how many still wait. */
export async function retryLifecycleWebhooks(now = new Date()): Promise<number> {
  const due = await WebhookDelivery.find({ deliveredAt: null, nextAttemptAt: { $ne: null, $lte: now } }).limit(500).lean<DeliveryDoc[]>();
  if (due.length) {
    const urls = new Map((await OAuthClient.find({ clientId: { $in: [...new Set(due.map((d) => d.clientId))] } }).select("clientId lifecycleWebhookUri").lean()).map((c) => [c.clientId, (c.lifecycleWebhookUri as string | null) || null]));
    const gaveUp = new Map<string, number>();
    for (const d of due) {
      // Only the ones that ran out of tries; an app that took away its URL asked for that.
      if ((await attempt(d, urls.get(d.clientId) ?? null)) === "gave_up" && urls.get(d.clientId)) gaveUp.set(d.clientId, (gaveUp.get(d.clientId) ?? 0) + 1);
    }
    if (gaveUp.size) {
      const { noticeToAdmins } = await import("@/lib/notifications/notices");
      await noticeToAdmins({
        kind: "webhooks-gave-up",
        subject: "Apps stopped receiving lifecycle events",
        paragraphs: [
          `After ${MAX_ATTEMPTS} tries over several days, these apps didn't accept lifecycle events, which are now dropped: ${[...gaveUp].map(([app, n]) => `${app} (${n} event${n === 1 ? "" : "s"})`).join(", ")}.`,
          "They may have missed people being deactivated or deleted. Check each app's lifecycle webhook URL and logs.",
        ],
        action: { label: "Open apps", path: "/clients" },
      });
    }
  }
  return WebhookDelivery.countDocuments({ deliveredAt: null, nextAttemptAt: { $ne: null } });
}
