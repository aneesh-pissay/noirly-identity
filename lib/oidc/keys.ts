import { randomBytes } from "node:crypto";
import { exportJWK, exportPKCS8, exportSPKI, generateKeyPair, importPKCS8, importSPKI, type JWK } from "jose";
import { getEnv } from "@/lib/config/env";
import { recordEvent } from "@/lib/audit/event-log";
import { ADMIN_STREAM, SYSTEM_STREAM } from "@/lib/audit/chain";
import { openSecret, sealSecret } from "@/lib/security/encryption";
import { SigningKey, type SigningKeyDocument, type SigningKeyState } from "@/models/SigningKey";

/**
 * Identity's signing keys, with rotation.
 *
 * Keys live in the database, private halves sealed with ENCRYPTION_KEY. The
 * key in JWT_PRIVATE_KEY / JWT_PUBLIC_KEY / JWT_KEY_ID only seeds the first
 * one; after that, rotate with `npm run keys:rotate` (on a schedule) or from
 * the admin API. A rollover goes:
 *   1. a `next` key is published in JWKS, signing nothing yet;
 *   2. once it has been published for SIGNING_KEY_PREPUBLISH_HOURS (longer
 *      than apps cache JWKS) and the active key is SIGNING_KEY_ROTATION_DAYS
 *      old, it becomes `active` and the old one `retired`;
 *   3. a retired key stays in JWKS until every token it signed has expired,
 *      then it's removed.
 * An emergency rotation skips the wait, and can drop the old key at once.
 */

type CryptoKeyLike = Awaited<ReturnType<typeof importPKCS8>>;

export type KeySet = {
  privateKey: CryptoKeyLike;
  publicKey: CryptoKeyLike;
  publicJwk: JWK;
  kid: string;
};

/** How long instances trust what they read; rotations reach every instance within this. */
const CACHE_MS = 60_000;

let cached: { at: number; active: KeySet; jwks: JWK[] } | null = null;

export function resetSigningKeyCache(): void {
  cached = null;
}

async function publicJwkFor(publicKeyPem: string, kid: string) {
  const publicKey = await importSPKI(publicKeyPem, "RS256", { extractable: true });
  const jwk = await exportJWK(publicKey);
  if (!jwk.n || Buffer.from(jwk.n, "base64url").length < 256) throw new Error("JWT signing requires an RSA key of at least 2048 bits");
  return { publicKey, jwk: { ...jwk, alg: "RS256", use: "sig", kid } satisfies JWK };
}

/** First run: the configured key becomes the active one. */
export async function ensureSigningKeys(): Promise<void> {
  if (await SigningKey.exists({})) return;
  const env = getEnv();
  await publicJwkFor(env.JWT_PUBLIC_KEY, env.JWT_KEY_ID);
  try {
    await SigningKey.updateOne(
      { kid: env.JWT_KEY_ID },
      { $setOnInsert: { kid: env.JWT_KEY_ID, state: "active", publicKeyPem: env.JWT_PUBLIC_KEY, privateKeySealed: sealSecret(env.JWT_PRIVATE_KEY, `signing-key:${env.JWT_KEY_ID}`), createdAt: new Date(), activatedAt: new Date() } },
      { upsert: true },
    );
  } catch (error) {
    // Another instance seeded it at the same moment.
    if ((error as { code?: number }).code !== 11000) throw error;
  }
}

async function load() {
  if (cached && Date.now() - cached.at < CACHE_MS) return cached;
  await ensureSigningKeys();
  const keys = await SigningKey.find({}).select("+privateKeySealed").sort({ activatedAt: -1, createdAt: -1 }).lean();
  // Mid-rotation two can be active for a moment: the newest signs.
  const active = keys.find((k) => k.state === "active") ?? keys.find((k) => k.state === "retired");
  if (!active) throw new Error("No signing key available");
  const { publicKey, jwk } = await publicJwkFor(active.publicKeyPem, active.kid);
  const privateKey = await importPKCS8(openSecret(active.privateKeySealed, `signing-key:${active.kid}`), "RS256");
  const order: Record<SigningKeyState, number> = { active: 0, next: 1, retired: 2 };
  const jwks = await Promise.all(
    [...keys].sort((a, b) => order[a.state] - order[b.state]).map(async (k) => (await publicJwkFor(k.publicKeyPem, k.kid)).jwk),
  );
  cached = { at: Date.now(), active: { privateKey, publicKey, publicJwk: jwk, kid: active.kid }, jwks };
  return cached;
}

/** The key that signs right now. */
export async function getSigningKeys(): Promise<KeySet> {
  return (await load()).active;
}

/** Every published key: the active one, the next one, and retired ones still in use. */
export async function getJwks(): Promise<{ keys: JWK[] }> {
  return { keys: (await load()).jwks };
}

/** How long a retired key stays published: past the longest-lived token it signed, plus JWKS caching. */
export function retiredKeyRetentionSeconds() {
  const longestToken = Math.max(getEnv().ACCESS_TOKEN_TTL_SECONDS, 15 * 60);
  return Math.max(longestToken + 2 * 3600, 86_400);
}

async function createKey(state: SigningKeyState, now: Date) {
  const { publicKey, privateKey } = await generateKeyPair("RS256", { modulusLength: 2048, extractable: true });
  const kid = `nik-${now.toISOString().slice(0, 10).replace(/-/g, "")}-${randomBytes(4).toString("hex")}`;
  await SigningKey.create({
    kid,
    state,
    publicKeyPem: await exportSPKI(publicKey),
    privateKeySealed: sealSecret(await exportPKCS8(privateKey), `signing-key:${kid}`),
    createdAt: now,
    activatedAt: state === "active" ? now : null,
  });
  return kid;
}

export type RotationResult = { created: string[]; activated: string | null; retired: string[]; removed: string[] };

/**
 * One step of the schedule (safe to run as often as you like), or with
 * `emergency` an immediate rotation; `dropOld` also unpublishes the old key at
 * once, so tokens it signed stop verifying (for a leaked key).
 */
export async function rotateSigningKeys(options: { now?: Date; emergency?: boolean; dropOld?: boolean; actorId?: string } = {}): Promise<RotationResult> {
  const now = options.now ?? new Date();
  const env = getEnv();
  await ensureSigningKeys();
  const result: RotationResult = { created: [], activated: null, retired: [], removed: [] };

  // Retired keys whose tokens have all expired.
  const expired = await SigningKey.find({ state: "retired", removeAfter: { $lte: now } }).select("kid").lean();
  if (expired.length) {
    await SigningKey.deleteMany({ _id: { $in: expired.map((k) => k._id) } });
    result.removed.push(...expired.map((k) => k.kid));
  }

  const active = await SigningKey.findOne({ state: "active" }).sort({ activatedAt: -1 }).lean();
  let next = await SigningKey.findOne({ state: "next" }).sort({ createdAt: 1 }).lean();
  if (!next) {
    const kid = await createKey("next", now);
    result.created.push(kid);
    next = await SigningKey.findOne({ kid }).lean();
  }

  const age = active?.activatedAt ? now.getTime() - active.activatedAt.getTime() : Infinity;
  const due = options.emergency || age >= env.SIGNING_KEY_ROTATION_DAYS * 86_400_000;
  const published = now.getTime() - next!.createdAt.getTime() >= env.SIGNING_KEY_PREPUBLISH_HOURS * 3_600_000;
  if (due && (options.emergency || published)) {
    await SigningKey.updateOne({ _id: next!._id }, { $set: { state: "active", activatedAt: now } });
    result.activated = next!.kid;
    const old = await SigningKey.find({ state: "active", _id: { $ne: next!._id } }).select("kid").lean();
    if (options.dropOld) {
      await SigningKey.deleteMany({ _id: { $in: old.map((k) => k._id) } });
      result.removed.push(...old.map((k) => k.kid));
    } else {
      await SigningKey.updateMany(
        { _id: { $in: old.map((k) => k._id) } },
        { $set: { state: "retired", retiredAt: now, removeAfter: new Date(now.getTime() + retiredKeyRetentionSeconds() * 1000) } },
      );
      result.retired.push(...old.map((k) => k.kid));
    }
    // The following rollover's key goes out now, well ahead of its turn.
    result.created.push(await createKey("next", now));
  }

  if (result.activated || result.removed.length) {
    resetSigningKeyCache();
    const stream = options.actorId ? ADMIN_STREAM : SYSTEM_STREAM;
    if (result.activated) {
      await recordEvent({ action: "signing_key.rotated", stream, subjectId: null, actorId: options.actorId ?? null, data: { from: active?.kid ?? null, to: result.activated, emergency: Boolean(options.emergency), droppedOld: Boolean(options.dropOld) } });
    }
    const unpublished = options.dropOld ? result.removed : result.removed.filter((kid) => !result.retired.includes(kid));
    if (unpublished.length) {
      await recordEvent({ action: "signing_key.removed", stream, subjectId: null, actorId: options.actorId ?? null, data: { kids: unpublished } });
    }
  }
  return result;
}

/** What the admin sees: never the private halves. */
export async function listSigningKeys() {
  const keys = await SigningKey.find({}).sort({ createdAt: -1 }).lean<SigningKeyDocument[]>();
  return keys.map((k) => ({
    kid: k.kid,
    state: k.state,
    createdAt: k.createdAt.toISOString(),
    activatedAt: k.activatedAt?.toISOString() ?? null,
    retiredAt: k.retiredAt?.toISOString() ?? null,
    removeAfter: k.removeAfter?.toISOString() ?? null,
  }));
}
