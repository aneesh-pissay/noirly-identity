import { createHash } from "node:crypto";
import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { recordEvent, type RequestMeta } from "@/lib/audit/event-log";
import { checkAvatar } from "@/lib/account/avatar-image";
import { getEnv } from "@/lib/config/env";
import { consumeRateLimit } from "@/lib/security/shared-rate-limit";
import { Avatar } from "@/models/Avatar";
import { User } from "@/models/User";

/**
 * Uploaded profile photos. The photo is kept here and served from Identity
 * at an address that changes with the photo; that address is the account's
 * avatarUrl, which apps see as the `picture` claim.
 */

/** Where an account's current photo is served. */
export function avatarUrlFor(userId: string, hash: string) {
  return `${getEnv().APP_URL}/api/avatars/${userId}/${hash}`;
}

function oid(id: string) {
  if (!Types.ObjectId.isValid(id)) throw new AppError("Invalid account", 400, "invalid_request");
  return new Types.ObjectId(id);
}

export async function setAvatar(userId: string, bytes: Uint8Array, declaredType: string | null, meta: RequestMeta = {}) {
  const limited = await consumeRateLimit(`avatar:${userId}`, 10, 3600);
  if (!limited.allowed) throw new AppError("Too many photo changes. Try again later.", 429, "rate_limited");
  const checked = checkAvatar(bytes, declaredType);
  if (!checked.ok) throw new AppError(checked.error, 400, "invalid_image");
  const hash = createHash("sha256").update(bytes).digest("hex").slice(0, 24);
  const user = await User.findById(oid(userId));
  if (!user) throw new AppError("Authentication required", 401, "unauthorized");
  await Avatar.updateOne(
    { userId: user._id },
    { $set: { contentType: checked.image.type, data: Buffer.from(bytes), hash, width: checked.image.width, height: checked.image.height } },
    { upsert: true },
  );
  user.avatarUrl = avatarUrlFor(userId, hash);
  await user.save();
  await recordEvent({ action: "account.profile_updated", subjectId: user._id, request: meta, data: { fields: ["avatarUrl"], uploaded: true } });
  return { avatarUrl: user.avatarUrl };
}

/** Removes the photo, uploaded or from Google, so apps show their own placeholder. */
export async function removeAvatar(userId: string, meta: RequestMeta = {}) {
  const user = await User.findById(oid(userId));
  if (!user) throw new AppError("Authentication required", 401, "unauthorized");
  await Avatar.deleteOne({ userId: user._id });
  if (user.avatarUrl) {
    user.avatarUrl = null;
    await user.save();
    await recordEvent({ action: "account.profile_updated", subjectId: user._id, request: meta, data: { fields: ["avatarUrl"], removed: true } });
  }
  return { avatarUrl: null };
}

/** The photo at an address, if it's still the account's current one. */
export async function readAvatar(userId: string, hash: string) {
  if (!Types.ObjectId.isValid(userId) || !/^[a-f0-9]{24}$/.test(hash)) return null;
  const doc = await Avatar.findOne({ userId: new Types.ObjectId(userId), hash }).select("contentType data").lean();
  if (!doc) return null;
  // Read back lean, the bytes are a BSON Binary rather than a Buffer.
  const raw = doc.data as unknown as Buffer | { buffer: Uint8Array; position?: number };
  const bytes = Buffer.isBuffer(raw) ? raw : raw.buffer.subarray(0, raw.position ?? raw.buffer.length);
  return { contentType: doc.contentType, bytes: new Uint8Array(bytes) };
}
