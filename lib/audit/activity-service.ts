import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { userStream } from "@/lib/audit/chain";
import {
  ACTIVITY_KINDS,
  actionsOf,
  activityKind,
  describeActivity,
  deviceLabel,
  isNotable,
  newDeviceSignIns,
  type ActivityItem,
  type ActivityKind,
} from "@/lib/audit/activity";
import { IdentityEvent } from "@/models/IdentityEvent";
import { OAuthClient } from "@/models/OAuthClient";

const PAGE = 30;
/** Sign-ins read back to tell new devices from known ones. */
const SIGN_IN_HISTORY = 2_000;

export type ActivityQuery = { kind?: string; before?: number };

/** One account's own security activity, newest first, a page at a time. */
export async function listActivity(userId: string, q: ActivityQuery = {}) {
  if (!Types.ObjectId.isValid(userId)) throw new AppError("Invalid account", 400, "invalid_request");
  const stream = userStream(userId);
  const filter: Record<string, unknown> = { stream };
  if (q.kind) {
    if (!(ACTIVITY_KINDS as readonly string[]).includes(q.kind)) throw new AppError("Unknown kind of activity", 400, "invalid_request");
    filter.action = { $in: actionsOf(q.kind as ActivityKind) };
  } else {
    filter.action = { $in: ACTIVITY_KINDS.flatMap(actionsOf) };
  }
  if (q.before !== undefined) {
    if (!Number.isInteger(q.before) || q.before < 1) throw new AppError("Invalid cursor", 400, "invalid_request");
    filter.seq = { $lt: q.before };
  }
  const docs = await IdentityEvent.find(filter).sort({ seq: -1 }).limit(PAGE + 1).lean();
  const page = docs.slice(0, PAGE);

  // New devices are judged against every earlier sign-in, not just this page.
  const signIns = await IdentityEvent.find({ stream, action: "auth.signed_in" }).sort({ seq: 1 }).limit(SIGN_IN_HISTORY).select("seq userAgent").lean();
  const fresh = newDeviceSignIns(signIns.map((s) => ({ seq: s.seq, device: deviceLabel(s.userAgent) })));

  const clientIds = [...new Set(page.map((d) => d.clientId).filter((c): c is string => Boolean(c)))];
  const clients = clientIds.length ? await OAuthClient.find({ clientId: { $in: clientIds } }).select("clientId name").lean() : [];
  const appName = new Map(clients.map((c) => [c.clientId, c.name]));

  const events: ActivityItem[] = page.map((doc) => {
    const newDevice = doc.action === "auth.signed_in" && fresh.has(doc.seq);
    return {
      seq: doc.seq,
      at: doc.at.toISOString(),
      kind: activityKind(doc.action)!,
      action: doc.action,
      title: describeActivity(doc.action, (doc.data ?? null) as Record<string, unknown> | null),
      device: deviceLabel(doc.userAgent),
      ipAddress: doc.ipAddress ?? null,
      // A deleted app still shows by its id.
      app: doc.clientId ? (appName.get(doc.clientId) ?? doc.clientId) : null,
      newDevice,
      notable: isNotable(doc.action, newDevice),
    };
  });
  return { events, nextBefore: docs.length > PAGE ? page.at(-1)!.seq : null };
}
