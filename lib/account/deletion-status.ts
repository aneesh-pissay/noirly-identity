import { AppError } from "@/lib/api/errors";
import { recordEvent } from "@/lib/audit/event-log";
import { retryDeletionRecord } from "@/lib/account/deletion-webhooks";
import { DeletedAccount, type DeletedAccountDocument } from "@/models/DeletedAccount";

/**
 * Coordinated deletion status: for each deleted account (kept 90 days, only
 * its opaque `sub`), which apps confirmed the deletion notice, which are still
 * being retried, and which gave up; admins can retry an account now.
 */

export type DeletionStatus = {
  sub: string;
  deletedAt: string;
  state: "confirmed" | "pending" | "failed";
  delivered: Array<{ clientId: string; at: string }>;
  pending: Array<{ clientId: string; attempts: number; lastError: string | null }>;
  failed: Array<{ clientId: string; attempts: number; lastError: string | null }>;
};

const view = (r: DeletedAccountDocument): DeletionStatus => ({
  sub: r.sub,
  deletedAt: r.deletedAt.toISOString(),
  state: r.failed?.length ? "failed" : r.pending.length ? "pending" : "confirmed",
  delivered: (r.delivered ?? []).map((d) => ({ clientId: d.clientId, at: d.at.toISOString() })),
  pending: r.pending.map(({ clientId, attempts, lastError }) => ({ clientId, attempts, lastError })),
  failed: (r.failed ?? []).map(({ clientId, attempts, lastError }) => ({ clientId, attempts, lastError })),
});

export async function listDeletionStatus(options: { state?: "confirmed" | "pending" | "failed"; sub?: string; limit?: number } = {}): Promise<DeletionStatus[]> {
  const filter: Record<string, unknown> = {};
  if (options.sub) filter.sub = options.sub;
  if (options.state === "failed") filter["failed.0"] = { $exists: true };
  if (options.state === "pending") Object.assign(filter, { "pending.0": { $exists: true }, "failed.0": { $exists: false } });
  if (options.state === "confirmed") Object.assign(filter, { "pending.0": { $exists: false }, "failed.0": { $exists: false } });
  const records = await DeletedAccount.find(filter).sort({ deletedAt: -1 }).limit(Math.min(options.limit ?? 50, 200)).lean<DeletedAccountDocument[]>();
  return records.map(view);
}

/** Retries every app that hasn't confirmed one account's deletion, including those given up on. */
export async function retryDeletionNow(sub: string, actorId: string): Promise<DeletionStatus> {
  const record = await DeletedAccount.findOne({ sub }).lean<DeletedAccountDocument>();
  if (!record) throw new AppError("No deletion record for that account", 404, "not_found");
  await retryDeletionRecord(record, 20, true);
  await recordEvent({ action: "admin.deletion_retried", stream: "admin", actorId, subjectId: null, data: { sub } });
  return view((await DeletedAccount.findOne({ sub }).lean<DeletedAccountDocument>())!);
}
