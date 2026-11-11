import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { getEnv } from "@/lib/config/env";

/**
 * Secrets kept at rest (TOTP secrets, signing keys) are sealed with AES-256-GCM
 * under a key derived from `ENCRYPTION_KEY`. `context` binds a value to what
 * it is (say, a signing key's kid), so one can't be swapped for another.
 */
function encryptionKey() {
  return createHash("sha256").update(getEnv().ENCRYPTION_KEY).digest();
}

export function sealSecret(secret: string, context?: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(), iv);
  if (context) cipher.setAAD(Buffer.from(context, "utf8"));
  const body = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString("base64url");
}

export function openSecret(value: string, context?: string): string {
  const data = Buffer.from(value, "base64url");
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey(), data.subarray(0, 12));
  if (context) decipher.setAAD(Buffer.from(context, "utf8"));
  decipher.setAuthTag(data.subarray(12, 28));
  return Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]).toString("utf8");
}
