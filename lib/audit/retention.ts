import { Schema, model, models, type Model } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { ADMIN_STREAM, SYSTEM_STREAM } from "@/lib/audit/chain";
import { IdentityEvent } from "@/models/IdentityEvent";

/**
 * Audit retention. Events older than the configured number of days are
 * removed, stream by stream, keeping a checkpoint: the sequence number and
 * hash of the last event removed, so the rest of the stream still verifies
 * (lib/audit/event-log.ts starts from the checkpoint instead of the start).
 * Account streams and the admin and system streams can keep different
 * lengths; organization streams follow the admin length. Unset keeps
 * everything (the default).
 */

export type RetentionSettings = { accountDays: number | null; adminDays: number | null };

const settingsSchema = new Schema({
  _id: { type: String, default: "retention" },
  accountDays: { type: Number, default: null },
  adminDays: { type: Number, default: null },
  updatedAt: { type: Date, default: null },
});
const AuditSettings: Model<{ _id: string; accountDays: number | null; adminDays: number | null; updatedAt: Date | null }> =
  (models.AuditSettings as never) || model("AuditSettings", settingsSchema, "audit_settings");

const checkpointSchema = new Schema({
  stream: { type: String, required: true, unique: true },
  seq: { type: Number, required: true },
  hash: { type: String, required: true },
  purgedAt: { type: Date, required: true },
});
export const AuditCheckpoint: Model<{ stream: string; seq: number; hash: string; purgedAt: Date }> =
  (models.AuditCheckpoint as never) || model("AuditCheckpoint", checkpointSchema, "audit_checkpoints");

/** At least this long, so retention can't be used to erase recent history in a hurry. */
export const MIN_RETENTION_DAYS = 90;

export async function getRetention(): Promise<RetentionSettings> {
  const doc = await AuditSettings.findById("retention").lean();
  return { accountDays: doc?.accountDays ?? null, adminDays: doc?.adminDays ?? null };
}

export async function setRetention(input: RetentionSettings): Promise<RetentionSettings> {
  for (const days of [input.accountDays, input.adminDays]) {
    if (days !== null && (!Number.isInteger(days) || days < MIN_RETENTION_DAYS || days > 3650)) {
      throw new AppError(`Keep events between ${MIN_RETENTION_DAYS} days and 10 years, or forever`, 400, "invalid_request");
    }
  }
  await AuditSettings.updateOne({ _id: "retention" }, { $set: { ...input, updatedAt: new Date() } }, { upsert: true });
  return getRetention();
}

/** Removes events past their retention, leaving a checkpoint per stream. Returns how many went. */
export async function applyRetention(now = new Date()): Promise<number> {
  const settings = await getRetention();
  let removed = 0;
  const groups: Array<{ match: Record<string, unknown>; days: number | null }> = [
    { match: { stream: /^user:/ }, days: settings.accountDays },
    { match: { stream: { $in: [ADMIN_STREAM, SYSTEM_STREAM] } }, days: settings.adminDays },
    { match: { stream: /^org:/ }, days: settings.adminDays },
  ];
  for (const group of groups) {
    if (group.days === null) continue;
    const cutoff = new Date(now.getTime() - group.days * 86_400_000);
    const streams = await IdentityEvent.distinct("stream", { ...group.match, at: { $lt: cutoff } });
    for (const stream of streams) {
      const last = await IdentityEvent.findOne({ stream, at: { $lt: cutoff } }).sort({ seq: -1 }).select("seq hash").lean();
      if (!last) continue;
      await AuditCheckpoint.updateOne({ stream }, { $set: { seq: last.seq, hash: last.hash, purgedAt: now } }, { upsert: true });
      const result = await IdentityEvent.deleteMany({ stream, seq: { $lte: last.seq } }, { eventPurge: true });
      removed += result.deletedCount;
    }
  }
  return removed;
}

/** Where verification of a stream starts: after its checkpoint, if events were removed. */
export async function checkpointOf(stream: string) {
  return AuditCheckpoint.findOne({ stream }).lean();
}
