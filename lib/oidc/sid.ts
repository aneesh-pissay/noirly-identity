import { hmacSha256 } from "@/lib/security/crypto";

/**
 * The `sid` apps see for an Identity session: in ID tokens, and in logout
 * tokens so they know which of their sessions to end. Derived, so the
 * database id isn't handed out, and the same for every app.
 */
export function sessionSid(sessionId: unknown): string {
  return hmacSha256(`sid:${String(sessionId)}`).slice(0, 32);
}
