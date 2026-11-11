import { Session } from "@/models/Session";
import { acrFor } from "@/lib/auth/acr";
import { effectivePermissions, explain, type Subject } from "@/lib/authz/engine";
import type { CheckContext } from "@/lib/authz/conditions";

/**
 * Getting permissions to apps (default deny), two ways:
 * - the `permissions` scope: tokens scoped to an organization carry a
 *   `permissions` claim (ID token, UserInfo, JWT access tokens), worked out
 *   when they're issued;
 * - the permissions API (app/api/authz): an app or API asks, with the access
 *   token it holds, whether this person may do this now, answered live.
 * Conditions see the sign-in behind the token: how strong it was, whether the
 * device is trusted (a passkey or second step), and the country it came from.
 */

/** The moment-of-check context for a session's sign-in. */
export async function contextForSession(sessionId: unknown): Promise<CheckContext> {
  const session = sessionId ? await Session.findById(sessionId).select("methods place").lean() : null;
  const methods = session?.methods ?? [];
  const country = session?.place?.split(",").pop()?.trim() || null;
  return {
    acr: methods.length ? acrFor(methods) : null,
    deviceTrusted: methods.some((m) => m === "passkey" || m === "totp"),
    country: country && /^[A-Z]{2}$/.test(country) ? country : null,
  };
}

/** The `permissions` claim for a token scoped to an organization. */
export async function permissionsClaim(organizationId: string, userId: string, sessionId: unknown): Promise<string[]> {
  return effectivePermissions(organizationId, { type: "user", id: userId }, await contextForSession(sessionId));
}

export async function checkForToken(organizationId: string, subject: Subject, sessionId: unknown, permission: string, resource: string | null) {
  const context = subject.type === "user" ? await contextForSession(sessionId) : {};
  const decision = await explain(organizationId, subject, permission, resource, context);
  return { allowed: decision.allowed };
}
