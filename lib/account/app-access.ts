import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { type AppAccessView } from "@/lib/account/app-scopes";
import { describeEachScope, describeScopesWithApis } from "@/lib/oauth/scope-descriptions";
import { appDisplayName } from "@/lib/oauth/environments";
import { environmentOf } from "@/lib/oauth/client-admin";
import { AccessToken } from "@/models/AccessToken";
import { AppAccess } from "@/models/AppAccess";
import { OAuthClient } from "@/models/OAuthClient";
import { RefreshToken } from "@/models/RefreshToken";
import { Session } from "@/models/Session";
import { recordEvent, type RequestMeta } from "@/lib/audit/event-log";
import { notifySessionsEnded } from "@/lib/oidc/backchannel-logout";

/** Reading details through UserInfo moves "last used" at most this often. */
const USERINFO_GAP_MS = 15 * 60_000;

type Id = Types.ObjectId | string;
const oid = (id: Id) => new Types.ObjectId(String(id));
const scopesOf = (scope: string) => scope.split(/\s+/).filter(Boolean);

/** An app was just given a token for this account: remember what it can see and when. */
export async function noteTokenIssued(userId: Id, clientId: string, scope: string, at = new Date()) {
  try {
    const existing = await AppAccess.findOne({ userId: oid(userId), clientId }).select("scopes").lean();
    const added = scopesOf(scope).filter((s) => !(existing?.scopes ?? []).includes(s));
    await AppAccess.updateOne(
      { userId: oid(userId), clientId },
      {
        $addToSet: { scopes: { $each: scopesOf(scope) } },
        // Remember when each scope was first granted.
        ...(added.length ? { $push: { grants: { $each: added.map((s) => ({ scope: s, at })) } } } : {}),
        $set: { lastUsedAt: at, removedAt: null },
        $setOnInsert: { firstUsedAt: at },
      },
      { upsert: true },
    );
  } catch (error) {
    // Never fails the sign-in it describes.
    console.error("App access not recorded:", error instanceof Error ? error.message : error);
  }
}

/**
 * True when this account has already given the app every one of these scopes
 * (through a token it was issued). Silent sign-in (prompt=none) may then skip
 * a consent page it can't show, since nothing new is being shared.
 */
export async function hasGrantedScopes(userId: Id, clientId: string, scope: string) {
  const wanted = scopesOf(scope);
  if (!wanted.length) return false;
  return Boolean(await AppAccess.exists({ userId: oid(userId), clientId, scopes: { $all: wanted } }));
}

/** An app read this account's details through UserInfo. */
export async function noteDetailsRead(userId: Id, clientId: string, at = new Date()) {
  await AppAccess.updateOne({ userId: oid(userId), clientId, lastUsedAt: { $lt: new Date(at.getTime() - USERINFO_GAP_MS) } }, { $set: { lastUsedAt: at } }).catch(() => undefined);
}

/**
 * Accounts that used apps before this was recorded: what their tokens still
 * show. Tokens expire and are cleaned away, so this is a floor, not history.
 */
async function fillFromTokens(userId: Types.ObjectId) {
  const tokens = [
    ...(await RefreshToken.find({ userId }).select("clientId scope createdAt").lean()),
    ...(await AccessToken.find({ userId }).select("clientId scope createdAt").lean()),
  ].sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
  for (const token of tokens) await noteTokenIssued(userId, token.clientId, token.scope, token.createdAt);
}

/** Every app that has had this account's details, most recently used first. */
export async function listAppAccess(userId: string): Promise<AppAccessView[]> {
  if (!Types.ObjectId.isValid(userId)) throw new AppError("Invalid account", 400, "invalid_request");
  const id = oid(userId);
  if (!(await AppAccess.exists({ userId: id }))) await fillFromTokens(id);
  // Apps whose access the person removed stay out of the list until they're used again.
  const rows = await AppAccess.find({ userId: id, removedAt: null }).sort({ lastUsedAt: -1 }).lean();
  if (!rows.length) return [];
  const clientIds = rows.map((r) => r.clientId);
  const now = new Date();
  // A token only works while its session does (lib/tokens/token-service.ts).
  const sessions = await Session.distinct("_id", { userId: id, revokedAt: null, expiresAt: { $gt: now } });
  const working = { userId: id, clientId: { $in: clientIds }, sessionId: { $in: sessions }, revokedAt: null, expiresAt: { $gt: now } };
  const [clients, liveAccess, liveRefresh] = await Promise.all([
    OAuthClient.find({ clientId: { $in: clientIds } }).select("clientId name clientType environment redirectUris").lean(),
    AccessToken.distinct("clientId", working),
    RefreshToken.distinct("clientId", working),
  ]);
  const byId = new Map(clients.map((c) => [c.clientId, c]));
  const live = new Set([...liveAccess, ...liveRefresh]);
  const [canSee, granted] = await Promise.all([
    Promise.all(rows.map((row) => describeScopesWithApis(row.scopes))),
    Promise.all(rows.map((row) => describeEachScope(row.scopes))),
  ]);
  return rows.map((row, index) => {
    const client = byId.get(row.clientId);
    return {
      clientId: row.clientId,
      // An app since removed still shows, by its id.
      name: client ? appDisplayName(client.name, environmentOf(client)) : row.clientId,
      kind: client?.clientType === "public" ? "mobile" : "web",
      canSee: canSee[index]!,
      // Each thing it may see, and since when.
      grants: granted[index]!.map(({ scope, text }) => {
        const at = row.grants?.find((g) => g.scope === scope)?.at ?? row.firstUsedAt;
        return { scope, text, since: at.toISOString() };
      }),
      scopes: row.scopes,
      firstUsedAt: row.firstUsedAt.toISOString(),
      lastUsedAt: row.lastUsedAt.toISOString(),
      signedIn: live.has(row.clientId),
    };
  });
}

/**
 * The person takes an app's access away: every token it holds for them stops
 * working, it's told to end its own sessions (back-channel logout), what it
 * was granted is forgotten, and next time it must ask on the consent screen,
 * even if it normally doesn't. Returns how many tokens were revoked.
 */
export async function removeAppAccess(userId: string, clientId: string, meta: RequestMeta = {}) {
  if (!Types.ObjectId.isValid(userId)) throw new AppError("Invalid account", 400, "invalid_request");
  const id = oid(userId);
  const access = await AppAccess.findOne({ userId: id, clientId, removedAt: null }).select("_id").lean();
  if (!access) throw new AppError("That app doesn't have access to your account", 404, "not_found");
  const now = new Date();
  const [accessTokens, refreshTokens] = await Promise.all([
    AccessToken.updateMany({ userId: id, clientId, revokedAt: null }, { $set: { revokedAt: now } }),
    RefreshToken.updateMany({ userId: id, clientId, revokedAt: null }, { $set: { revokedAt: now } }),
  ]);
  await notifySessionsEnded([{ _id: null, userId: id, appIds: [clientId] }], { onlyClientId: clientId, everyAppSession: true });
  await Promise.all([
    AppAccess.updateOne({ _id: access._id }, { $set: { scopes: [], grants: [], removedAt: now, consentRequired: true } }),
    // Devices no longer list it among the apps they opened.
    Session.updateMany({ userId: id, appIds: clientId }, { $pull: { appIds: clientId } }),
  ]);
  const revoked = accessTokens.modifiedCount + refreshTokens.modifiedCount;
  await recordEvent({ action: "oauth.access_removed", subjectId: id, clientId, request: meta, data: { tokensRevoked: revoked } });
  return { revoked };
}

/** After a removal, the app must ask again (app/api/oauth/authorize). */
export async function consentRequiredAgain(userId: Id, clientId: string) {
  return Boolean(await AppAccess.exists({ userId: oid(userId), clientId, consentRequired: true }));
}

/** The person agreed on the consent screen (app/api/oauth/consent). */
export async function consentGivenAgain(userId: Id, clientId: string) {
  await AppAccess.updateOne({ userId: oid(userId), clientId }, { $set: { consentRequired: false } });
}
