"use client";
import { getCsrf } from "@/lib/auth/csrf-client";

/** A refused security change, with the server's reason code (`reauth_required` means "sign in again first"). */
export class SecurityRequestError extends Error {
  constructor(message: string, readonly code: string | undefined) {
    super(message);
  }
}

/** True when the change was refused only because the sign-in is more than five minutes old. */
export const needsFreshSignIn = (error: unknown) => error instanceof SecurityRequestError && error.code === "reauth_required";

/** Where "Sign in again" goes: the login page, then straight back to this account page. */
export const reauthHref = (returnTo: string) => `/login?return_to=${encodeURIComponent(returnTo)}&reauth=1`;

export async function securityRequest<T>(path: string, body: Record<string, unknown>): Promise<T> {
  const response = await fetch(path, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": await getCsrf() }, body: JSON.stringify(body) });
  const data = await response.json();
  if (!response.ok) throw new SecurityRequestError(data.message ?? "Security request failed", data.error);
  return data as T;
}
