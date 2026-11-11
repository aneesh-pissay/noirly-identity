import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { sha256 } from "@/lib/security/crypto";
import { IdentityEvent, type IdentityEventDocument } from "@/models/IdentityEvent";
import {
  ADMIN_STREAM,
  ChainChecker,
  GENESIS_HASH,
  IDENTITY_ACTIONS,
  canonicalJson,
  hashInput,
  isEventStream,
  userStream,
  type ChainCheck,
  type EventFields,
  type EventStream,
  type IdentityAction,
  type IdentityEventView,
} from "@/lib/audit/chain";

/**
 * Two writers racing for the same place in a stream: one wins, the other
 * tries the next. Waits grow with each try, so a burst of writers to one
 * stream spreads out instead of colliding again and again.
 */
const MAX_TRIES = 30;
const PAGE = 500;

type Id = string | Types.ObjectId;

export type RequestMeta = { ipAddress?: string | null; userAgent?: string | null; place?: string | null; deviceId?: string | null };

export type EventInput = {
  action: IdentityAction;
  /** Whose account it's about; its stream unless `stream` says otherwise. */
  subjectId?: Id | null;
  /** Who did it; defaults to the subject (people act on their own accounts). */
  actorId?: Id | null;
  stream?: EventStream;
  clientId?: string | null;
  request?: RequestMeta;
  data?: unknown;
};

const idOf = (id: Id | null | undefined) => (id ? String(id) : null);

/**
 * Adds an event to the end of its stream. It runs after the thing it
 * records has happened, so it never fails that: an event that can't get a
 * place in the chain is logged loudly instead.
 */
export async function recordEvent(input: EventInput): Promise<void> {
  const subjectId = idOf(input.subjectId);
  const actorId = input.actorId === undefined ? subjectId : idOf(input.actorId);
  const stream = input.stream ?? (subjectId ? userStream(subjectId) : ADMIN_STREAM);
  try {
    // Stored as plain JSON, so it reads back exactly as it was hashed.
    const data = JSON.parse(canonicalJson(input.data ?? null)) as unknown;
    for (let attempt = 0; attempt < MAX_TRIES; attempt++) {
      const last = await IdentityEvent.findOne({ stream }).sort({ seq: -1 }).select("seq hash").lean();
      const prevHash = last?.hash ?? GENESIS_HASH;
      const fields: EventFields = {
        stream,
        seq: (last?.seq ?? 0) + 1,
        at: new Date().toISOString(),
        action: input.action,
        actorId,
        subjectId,
        clientId: input.clientId ?? null,
        ipAddress: input.request?.ipAddress ?? null,
        userAgent: input.request?.userAgent?.slice(0, 300) ?? null,
        data,
      };
      try {
        await IdentityEvent.create({
          ...fields,
          action: input.action,
          at: new Date(fields.at),
          actorId: actorId ? new Types.ObjectId(actorId) : null,
          subjectId: subjectId ? new Types.ObjectId(subjectId) : null,
          prevHash,
          hash: sha256(hashInput(prevHash, fields)),
        });
        // Admins' alert rules on chosen events (lib/audit/alert-rules.ts).
        const { notifyAlertRules } = await import("@/lib/audit/alert-rules");
        await notifyAlertRules(fields).catch((error) => console.error("Audit alert not sent:", error instanceof Error ? error.message : error));
        // Things the account's owner should hear about at once (lib/security/alerts.ts).
        if (subjectId && stream === userStream(subjectId)) {
          const { alertsFor, sendSecurityAlert } = await import("@/lib/security/alerts");
          if (alertsFor(input.action)) {
            await sendSecurityAlert(input.action, subjectId, (data ?? {}) as Record<string, unknown>).catch((error) =>
              console.error("Security alert not sent:", error instanceof Error ? error.message : error),
            );
          }
        }
        return;
      } catch (error) {
        if ((error as { code?: number }).code !== 11000) throw error;
        await new Promise((resolve) => setTimeout(resolve, Math.random() * 10 * Math.min(attempt + 1, 10)));
      }
    }
    throw new Error("No place in the event chain after several tries");
  } catch (error) {
    console.error(`Identity event not written (${input.action} in ${stream}):`, error instanceof Error ? error.message : error);
  }
}

function fieldsOf(doc: IdentityEventDocument): EventFields {
  return {
    stream: doc.stream,
    seq: doc.seq,
    at: doc.at.toISOString(),
    action: doc.action,
    actorId: doc.actorId ? String(doc.actorId) : null,
    subjectId: doc.subjectId ? String(doc.subjectId) : null,
    clientId: doc.clientId ?? null,
    ipAddress: doc.ipAddress ?? null,
    userAgent: doc.userAgent ?? null,
    data: doc.data ?? null,
  };
}

function view(doc: IdentityEventDocument): IdentityEventView & { id: string } {
  return { id: String(doc._id), ...fieldsOf(doc), hash: doc.hash };
}

export type EventQuery = {
  stream?: string;
  action?: string;
  subjectId?: string;
  actorId?: string;
  clientId?: string;
  ipAddress?: string;
  from?: Date;
  to?: Date;
  before?: string;
  limit?: number;
};

/** A page of events, newest first, filtered by stream, action (or "auth." for a family) and account. */
export async function listEvents(q: EventQuery = {}) {
  const filter: Record<string, unknown> = {};
  if (q.stream) {
    if (!isEventStream(q.stream)) throw new AppError("Unknown stream", 400, "invalid_request");
    filter.stream = q.stream;
  }
  if (q.action) {
    if (q.action.endsWith(".")) {
      const family = IDENTITY_ACTIONS.filter((a) => a.startsWith(q.action!));
      if (!family.length) throw new AppError("Unknown action", 400, "invalid_request");
      filter.action = { $in: family };
    } else {
      if (!(IDENTITY_ACTIONS as readonly string[]).includes(q.action)) throw new AppError("Unknown action", 400, "invalid_request");
      filter.action = q.action;
    }
  }
  if (q.subjectId) {
    if (!Types.ObjectId.isValid(q.subjectId)) throw new AppError("Invalid account id", 400, "invalid_request");
    filter.subjectId = new Types.ObjectId(q.subjectId);
  }
  if (q.actorId) {
    if (!Types.ObjectId.isValid(q.actorId)) throw new AppError("Invalid actor id", 400, "invalid_request");
    filter.actorId = new Types.ObjectId(q.actorId);
  }
  if (q.clientId) filter.clientId = q.clientId;
  if (q.ipAddress) filter.ipAddress = q.ipAddress;
  if (q.from || q.to) filter.at = { ...(q.from ? { $gte: q.from } : {}), ...(q.to ? { $lt: q.to } : {}) };
  if (q.before) {
    if (!Types.ObjectId.isValid(q.before)) throw new AppError("Invalid cursor", 400, "invalid_request");
    filter._id = { $lt: new Types.ObjectId(q.before) };
  }
  const limit = Math.min(Math.max(q.limit ?? 50, 1), 200);
  const docs = await IdentityEvent.find(filter).sort({ _id: -1 }).limit(limit + 1).lean<IdentityEventDocument[]>();
  const page = docs.slice(0, limit);
  return { events: page.map(view), nextBefore: docs.length > limit ? String(page.at(-1)!._id) : null };
}

/** A whole stream, checked from its first event, a page at a time. */
export async function verifyStream(stream: string): Promise<ChainCheck & { stream: string; checkedAt: string }> {
  if (!isEventStream(stream)) throw new AppError("Unknown stream", 400, "invalid_request");
  // After a retention purge, verification starts from the checkpoint it left (lib/audit/retention.ts).
  const { checkpointOf } = await import("@/lib/audit/retention");
  const checkpoint = await checkpointOf(stream);
  const checker = new ChainChecker(sha256, checkpoint);
  let after = checkpoint?.seq ?? 0;
  for (;;) {
    const docs = await IdentityEvent.find({ stream, seq: { $gt: after } }).sort({ seq: 1 }).limit(PAGE).lean<IdentityEventDocument[]>();
    for (const doc of docs) checker.add({ ...fieldsOf(doc), prevHash: doc.prevHash, hash: doc.hash });
    const result = checker.result();
    if (!result.ok || docs.length < PAGE) return { ...result, stream, checkedAt: new Date().toISOString() };
    after = docs.at(-1)!.seq;
  }
}

/** When an account is deleted: its stream goes with it (the deletion itself is kept in the system stream). */
export async function purgeUserEvents(userId: Id) {
  await IdentityEvent.deleteMany({ stream: userStream(String(userId)) }, { eventPurge: true });
}

/**
 * Events for export (authentication events across accounts, the admin and
 * system logs, or both), oldest first, between two moments, with their
 * hashes so the export can be checked against the chain.
 */
export async function exportEvents(kind: "auth" | "admin" | "all", from: Date, to: Date, max = 50_000) {
  const filter: Record<string, unknown> = { at: { $gte: from, $lt: to } };
  if (kind === "auth") filter.action = { $in: IDENTITY_ACTIONS.filter((a) => a.startsWith("auth.") || a.startsWith("mfa.") || a.startsWith("passkey.") || a.startsWith("password.") || a.startsWith("recovery.")) };
  if (kind === "admin") filter.stream = { $in: [ADMIN_STREAM, "system"] };
  const docs = await IdentityEvent.find(filter).sort({ at: 1, seq: 1 }).limit(max).lean<IdentityEventDocument[]>();
  return docs.map((doc) => ({ ...fieldsOf(doc), prevHash: doc.prevHash, hash: doc.hash }));
}
