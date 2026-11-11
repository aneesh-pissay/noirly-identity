import { randomInt } from "node:crypto";
import { hmacSha256, safeEqualHex } from "@/lib/security/crypto";

/**
 * Six-digit codes sent by email, for typing in where a link is awkward (a
 * TV, a phone app, another device). A code is only good for the one
 * record it was made for (a sign-in link, a verification), is kept as a
 * keyed hash, and dies after MAX_CODE_ATTEMPTS wrong tries, so its small
 * size can't be guessed through.
 */

export const MAX_CODE_ATTEMPTS = 5;

export function newEmailCode(): string {
  return String(randomInt(0, 1_000_000)).padStart(6, "0");
}

export function isEmailCode(value: string): boolean {
  return /^\d{6}$/.test(value);
}

/** Bound to its record, so the same digits elsewhere mean nothing. */
export function emailCodeHash(recordId: string, code: string): string {
  return hmacSha256(`email-code:${recordId}:${code}`);
}

export function emailCodeMatches(recordId: string, code: string, stored: string | null | undefined): boolean {
  return Boolean(stored) && isEmailCode(code) && safeEqualHex(emailCodeHash(recordId, code), stored!);
}

/** "123456" → "123 456", easier to read off one screen and type into another. */
export function spacedCode(code: string): string {
  return `${code.slice(0, 3)} ${code.slice(3)}`;
}
