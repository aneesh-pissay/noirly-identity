import { AppError } from "@/lib/api/errors";
import { recordEvent } from "@/lib/audit/event-log";
import { AppAccess } from "@/models/AppAccess";
import { OAuthClient } from "@/models/OAuthClient";

/**
 * Claim minimization review: every app should get only the claims it needs.
 * For each app, the scopes it may ask for are set against those anyone has
 * actually granted it (AppAccess keeps every grant). A scope nobody has
 * granted in an app that's been live a while is not needed, and an admin can
 * trim it from the app's allowed scopes. `openid` is never flagged.
 */

const SETTLE_DAYS = 30;
const ALWAYS_KEPT = new Set(["openid"]);

export type ClaimReview = {
  clientId: string;
  name: string;
  allowed: string[];
  /** Scope → how many people have granted it. */
  granted: Record<string, number>;
  /** Allowed but never granted (once the app has settled). */
  unused: string[];
  /** Too new to judge: fewer than SETTLE_DAYS since it was registered. */
  settling: boolean;
};

export async function reviewClaims(clientId?: string): Promise<ClaimReview[]> {
  const clients = await OAuthClient.find(clientId ? { clientId } : {}).select("clientId name allowedScopes createdAt").sort({ name: 1 }).lean();
  const counts = await AppAccess.aggregate<{ _id: { clientId: string; scope: string }; n: number }>([
    { $match: { clientId: { $in: clients.map((c) => c.clientId) } } },
    { $unwind: "$scopes" },
    { $group: { _id: { clientId: "$clientId", scope: "$scopes" }, n: { $sum: 1 } } },
  ]);
  const byClient = new Map<string, Record<string, number>>();
  for (const { _id, n } of counts) {
    const granted = byClient.get(_id.clientId) ?? {};
    granted[_id.scope] = n;
    byClient.set(_id.clientId, granted);
  }
  const settledBefore = Date.now() - SETTLE_DAYS * 86_400_000;
  return clients.map((c) => {
    const granted = byClient.get(c.clientId) ?? {};
    const allowed = [...(c.allowedScopes as string[])];
    const createdAt = (c as { createdAt?: Date }).createdAt;
    const settling = !createdAt || createdAt.getTime() > settledBefore;
    return {
      clientId: c.clientId,
      name: c.name,
      allowed,
      granted,
      unused: settling ? [] : allowed.filter((s) => !ALWAYS_KEPT.has(s) && !granted[s]),
      settling,
    };
  });
}

/** Removes scopes from an app's allowed scopes (never `openid`). */
export async function trimScopes(clientId: string, scopes: string[], actorId: string): Promise<ClaimReview> {
  const remove = [...new Set(scopes)].filter((s) => !ALWAYS_KEPT.has(s));
  if (remove.length === 0) throw new AppError("Nothing to remove", 400, "invalid_request");
  const result = await OAuthClient.updateOne({ clientId }, { $pull: { allowedScopes: { $in: remove } } });
  if (result.matchedCount === 0) throw new AppError("App not found", 404, "not_found");
  await recordEvent({ action: "client.updated", stream: "admin", actorId, subjectId: null, clientId, data: { removedScopes: remove, reason: "claim review" } });
  return (await reviewClaims(clientId))[0]!;
}
