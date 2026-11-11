import { randomUUID } from "node:crypto";
import { SignJWT } from "jose";
import { Schema, Types, model, models, type Model } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { recordEvent } from "@/lib/audit/event-log";
import { getEnv } from "@/lib/config/env";
import { sendEmail } from "@/lib/email/email-service";
import { buildNoticeEmail } from "@/lib/email/templates";
import { getSigningKeys } from "@/lib/oidc/keys";
import { consumeRateLimit } from "@/lib/security/shared-rate-limit";
import { exportIdentityData } from "@/lib/account/closure";
import { AppAccess } from "@/models/AppAccess";
import { OAuthClient } from "@/models/OAuthClient";
import { User } from "@/models/User";

/**
 * Personal data export across Noirly apps, in one request. Identity's own
 * data is gathered at once; every app the person has used that registered a
 * `dataExportUri` is asked for theirs: Identity POSTs a Security Event Token
 * (`application/secevent+jwt`, signed with the JWKS keys, `aud` = the app,
 * `sub` = the person, event `https://noirly.dev/events/data-export-requested`)
 * and the app answers with the person's data as JSON (200), or 204 for none.
 * Apps that fail are retried by the scheduled job (MAX_ATTEMPTS); once every
 * app has answered or given up, the bundle is ready, the person is emailed,
 * and they download it signed in, for a week.
 */

export const DATA_EXPORT_EVENT = "https://noirly.dev/events/data-export-requested";
const MAX_ATTEMPTS = 5;
const MAX_PART_BYTES = 5 * 1024 * 1024;
const KEEP_DAYS = 7;

type Part = { clientId: string; appName: string; status: "pending" | "delivered" | "no_data" | "failed"; attempts: number; lastError: string | null; data: unknown };
type ExportDoc = { _id: Types.ObjectId; userId: Types.ObjectId; status: "collecting" | "ready"; identity: unknown; parts: Part[]; createdAt: Date; readyAt: Date | null; expiresAt: Date };

const exportSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
    status: { type: String, enum: ["collecting", "ready"], default: "collecting" },
    identity: { type: Schema.Types.Mixed, default: null },
    parts: {
      type: [new Schema({ clientId: String, appName: String, status: { type: String, default: "pending" }, attempts: { type: Number, default: 0 }, lastError: { type: String, default: null }, data: { type: Schema.Types.Mixed, default: null } }, { _id: false })],
      default: [],
    },
    readyAt: { type: Date, default: null },
    expiresAt: { type: Date, required: true, index: { expireAfterSeconds: 0 } },
  },
  { timestamps: { createdAt: true, updatedAt: false }, minimize: false },
);
export const DataExportRequest: Model<ExportDoc> = (models.DataExportRequest as never) || model("DataExportRequest", exportSchema, "data_exports");

export type ExportStatus = { id: string; status: "collecting" | "ready"; requestedAt: string; readyAt: string | null; expiresAt: string; apps: Array<{ name: string; status: Part["status"] }> };
const statusView = (e: ExportDoc): ExportStatus => ({
  id: String(e._id),
  status: e.status,
  requestedAt: e.createdAt.toISOString(),
  readyAt: e.readyAt ? e.readyAt.toISOString() : null,
  expiresAt: e.expiresAt.toISOString(),
  apps: e.parts.map((p) => ({ name: p.appName, status: p.status })),
});

async function signRequest(sub: string, clientId: string) {
  const keys = await getSigningKeys();
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ events: { [DATA_EXPORT_EVENT]: {} } })
    .setProtectedHeader({ alg: "RS256", kid: keys.kid, typ: "secevent+jwt" })
    .setIssuer(getEnv().OIDC_ISSUER)
    .setSubject(sub)
    .setAudience(clientId)
    .setIssuedAt(now)
    .setExpirationTime(now + 15 * 60)
    .setJti(randomUUID())
    .sign(keys.privateKey);
}

/** Asks one app; returns the part's new state. */
async function askApp(url: string, sub: string, part: Part): Promise<Part> {
  const attempts = part.attempts + 1;
  try {
    const response = await fetch(url, {
      method: "POST",
      redirect: "error",
      headers: { "content-type": "application/secevent+jwt", accept: "application/json" },
      body: await signRequest(sub, part.clientId),
      signal: AbortSignal.timeout(10_000),
      cache: "no-store",
    });
    if (response.status === 204) return { ...part, attempts, status: "no_data", lastError: null, data: null };
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const text = await response.text();
    if (text.length > MAX_PART_BYTES) throw new Error("Answer too large");
    return { ...part, attempts, status: "delivered", lastError: null, data: JSON.parse(text) as unknown };
  } catch (error) {
    const lastError = error instanceof Error ? error.message : "delivery failed";
    return { ...part, attempts, status: attempts >= MAX_ATTEMPTS ? "failed" : "pending", lastError, data: null };
  }
}

/** Collects what's still pending; marks the export ready (and emails) once nothing is. */
async function collect(exportId: Types.ObjectId) {
  const doc = await DataExportRequest.findById(exportId).lean<ExportDoc>();
  if (!doc || doc.status !== "collecting") return;
  const uris = new Map((await OAuthClient.find({ clientId: { $in: doc.parts.map((p) => p.clientId) } }).select("clientId dataExportUri").lean()).map((c) => [c.clientId, c.dataExportUri as string | null]));
  const parts = await Promise.all(doc.parts.map((part) => {
    if (part.status !== "pending") return part;
    const url = uris.get(part.clientId);
    return url ? askApp(url, String(doc.userId), part) : Promise.resolve({ ...part, status: "failed" as const, lastError: "The app no longer takes export requests" });
  }));
  const ready = parts.every((p) => p.status !== "pending");
  await DataExportRequest.updateOne({ _id: doc._id }, { $set: { parts, ...(ready ? { status: "ready", readyAt: new Date() } : {}) } });
  if (ready) {
    const user = await User.findById(doc.userId).select("email").lean();
    if (user) {
      await sendEmail({
        to: user.email,
        ...buildNoticeEmail({
          subject: "Your Noirly data is ready",
          paragraphs: [`Your data from Noirly Identity and ${parts.filter((p) => p.status === "delivered").length} app(s) is ready to download for ${KEEP_DAYS} days. You'll need to sign in.`],
          action: { label: "Download it", url: new URL("/account/privacy", getEnv().APP_URL).toString() },
        }),
        meta: { kind: "data-export-ready" },
      }).catch(() => undefined);
    }
  }
}

/** Starts an export of everything, Identity's and every app's (once a day). */
export async function requestDataExport(userId: string): Promise<ExportStatus> {
  const limit = await consumeRateLimit(`data-export:${userId}`, 1, 86_400);
  if (!limit.allowed) throw new AppError("You can ask for your data once a day. Your latest export is on your privacy page.", 429, "rate_limited");
  const id = new Types.ObjectId(userId);
  const used = await AppAccess.distinct("clientId", { userId: id });
  const clients = await OAuthClient.find({ clientId: { $in: used }, dataExportUri: { $nin: [null, ""] } }).select("clientId name").lean();
  const created = await DataExportRequest.create({
    userId: id,
    identity: await exportIdentityData(userId),
    parts: clients.map((c) => ({ clientId: c.clientId, appName: c.name, status: "pending", attempts: 0, lastError: null, data: null })),
    expiresAt: new Date(Date.now() + KEEP_DAYS * 86_400_000),
  });
  await recordEvent({ action: "account.data_exported", subjectId: userId, data: { apps: clients.length } });
  await collect(created._id);
  return statusView((await DataExportRequest.findById(created._id).lean<ExportDoc>())!);
}

export async function listDataExports(userId: string): Promise<ExportStatus[]> {
  return (await DataExportRequest.find({ userId: new Types.ObjectId(userId) }).sort({ createdAt: -1 }).limit(5).lean<ExportDoc[]>()).map(statusView);
}

/** The bundle, for its owner only, once ready. */
export async function downloadDataExport(userId: string, exportId: string) {
  if (!Types.ObjectId.isValid(exportId)) throw new AppError("Export not found", 404, "not_found");
  const doc = await DataExportRequest.findOne({ _id: new Types.ObjectId(exportId), userId: new Types.ObjectId(userId) }).lean<ExportDoc>();
  if (!doc) throw new AppError("Export not found", 404, "not_found");
  if (doc.status !== "ready") throw new AppError("Still collecting from your apps", 409, "not_ready");
  return {
    exportedAt: doc.readyAt?.toISOString() ?? null,
    identity: doc.identity,
    apps: Object.fromEntries(doc.parts.map((p) => [p.appName, p.status === "delivered" ? p.data : { unavailable: p.status === "no_data" ? "This app holds no data for you" : `This app didn't answer (${p.lastError ?? "unknown"})` }])),
  };
}

/** Retries exports still collecting (the scheduled job). */
export async function retryDataExports(): Promise<number> {
  const collecting = await DataExportRequest.find({ status: "collecting" }).select("_id").lean();
  for (const e of collecting) await collect(e._id);
  return DataExportRequest.countDocuments({ status: "collecting" });
}
