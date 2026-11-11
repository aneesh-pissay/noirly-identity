import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { AppError } from "@/lib/api/errors";
import { getEnv } from "@/lib/config/env";
import { consumeRateLimit } from "@/lib/security/shared-rate-limit";

/**
 * Sign-up abuse protection, without a third party watching anyone:
 * - a proof-of-work challenge: the browser spends about a second hashing
 *   before it may sign up, which is nothing to a person and a real cost to a
 *   script making thousands of accounts. Stateless (signed by Identity),
 *   short-lived, and each one works once;
 * - disposable email addresses refused;
 * - velocity limits: few sign-ups per address and per device each hour.
 */

const CHALLENGE_SECONDS = 600;

function bits() {
  const configured = Number(process.env.SIGNUP_POW_BITS);
  if (Number.isInteger(configured) && configured >= 0 && configured <= 24) return configured;
  return getEnv().NODE_ENV === "test" ? 4 : 16;
}

const sign = (payload: string) => createHmac("sha256", getEnv().SESSION_SECRET).update(`signup-pow:${payload}`).digest("base64url");

/** A challenge for the sign-up form: find `solution` so sha256(`challenge:solution`) starts with `bits` zero bits. */
export function issueSignupChallenge(now = Date.now()) {
  const payload = `${randomBytes(12).toString("base64url")}.${Math.floor(now / 1000) + CHALLENGE_SECONDS}.${bits()}`;
  return { challenge: `${payload}.${sign(payload)}`, bits: bits() };
}

export function leadingZeroBits(digest: Buffer) {
  let count = 0;
  for (const byte of digest) {
    if (byte === 0) { count += 8; continue; }
    count += Math.clz32(byte) - 24;
    break;
  }
  return count;
}

/** Checks a solved challenge, and spends it. */
export async function verifySignupChallenge(challenge: string | undefined, solution: string | undefined) {
  const refuse = () => { throw new AppError("Please try signing up again.", 400, "challenge_failed"); };
  if (!challenge || !solution || solution.length > 32 || challenge.length > 200) return refuse();
  const parts = challenge.split(".");
  if (parts.length !== 4) return refuse();
  const payload = parts.slice(0, 3).join(".");
  const expected = Buffer.from(sign(payload));
  const given = Buffer.from(parts[3]!);
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) return refuse();
  if (Number(parts[1]) * 1000 < Date.now()) return refuse();
  const digest = createHash("sha256").update(`${challenge}:${solution}`).digest();
  if (leadingZeroBits(digest) < Number(parts[2])) return refuse();
  // Each challenge works once.
  const spent = await consumeRateLimit(`signup-pow:${createHash("sha256").update(challenge).digest("hex")}`, 1, CHALLENGE_SECONDS);
  if (!spent.allowed) return refuse();
}

/** Domains handing out throwaway inboxes. Extend with DISPOSABLE_EMAIL_DOMAINS (comma separated). */
const DISPOSABLE = new Set([
  "mailinator.com", "guerrillamail.com", "guerrillamail.net", "sharklasers.com", "10minutemail.com", "10minutemail.net",
  "tempmail.com", "temp-mail.org", "temp-mail.io", "yopmail.com", "yopmail.net", "trashmail.com", "getnada.com",
  "dispostable.com", "maildrop.cc", "throwawaymail.com", "fakeinbox.com", "mintemail.com", "mohmal.com",
  "emailondeck.com", "tempinbox.com", "spamgourmet.com", "mailnesia.com", "moakt.com", "burnermail.io", "tempr.email",
]);

export function isDisposableEmail(email: string) {
  const domain = email.split("@")[1]?.toLowerCase() ?? "";
  const extra = (process.env.DISPOSABLE_EMAIL_DOMAINS ?? "").split(",").map((d) => d.trim().toLowerCase()).filter(Boolean);
  const blocked = new Set([...DISPOSABLE, ...extra]);
  // The domain or any parent of it (x.mailinator.com).
  const labels = domain.split(".");
  return labels.some((_, i) => blocked.has(labels.slice(i).join(".")));
}

/** Few sign-ups per address and per device each hour. */
export const SIGNUPS_PER_ADDRESS = 5;
export const SIGNUPS_PER_DEVICE = 3;

export async function checkSignupAllowed(email: string, meta: { ipAddress?: string | null; deviceId?: string | null }) {
  if (isDisposableEmail(email)) {
    throw new AppError("Use an email address you'll keep: temporary inboxes can't be used for an account.", 400, "disposable_email");
  }
  const checks = await Promise.all([
    meta.ipAddress ? consumeRateLimit(`signup-address:${meta.ipAddress}`, SIGNUPS_PER_ADDRESS, 3600) : null,
    meta.deviceId ? consumeRateLimit(`signup-device:${meta.deviceId}`, SIGNUPS_PER_DEVICE, 3600) : null,
  ]);
  for (const result of checks) {
    if (result && !result.allowed) throw new AppError("Too many new accounts from here. Try again later.", 429, "rate_limited", { retryAfterSeconds: result.retryAfterSeconds });
  }
}
