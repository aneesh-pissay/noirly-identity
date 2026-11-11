/** Session-lifetime limits and choices, safe to import in the browser (lib/sessions/lifetime.ts uses them). */

/**
 * How long sessions last, for one account.
 * - `idleSeconds`: a session left unused this long ends. Null: no idle limit.
 * - `absoluteSeconds`: a session ends this long after sign-in, however busy.
 *   Null: Identity's default (`SESSION_TTL_SECONDS`).
 * An account can only tighten the default, never loosen it.
 */
export type SessionPolicy = { idleSeconds: number | null; absoluteSeconds: number | null };

export const IDLE_MIN_SECONDS = 15 * 60;
export const IDLE_MAX_SECONDS = 30 * 86_400;
export const ABSOLUTE_MIN_SECONDS = 60 * 60;

/** The choices the account page offers; the route accepts any value within the limits. */
export const IDLE_CHOICES = [null, 15 * 60, 60 * 60, 8 * 3600, 86_400, 7 * 86_400] as const;
export const ABSOLUTE_CHOICES = [null, 8 * 3600, 86_400, 7 * 86_400] as const;
