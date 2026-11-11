import type { SignInMethod } from "@/lib/audit/chain";

/**
 * How strongly a session was authenticated, in the terms OpenID Connect
 * apps read: `amr` (the methods, RFC 8176 values where there is one) and
 * `acr` (one of two levels). An app asks for a level with `acr_values`, or
 * for a recent sign-in with `max_age` / `prompt=login`, before a sensitive
 * action; Identity steps the person up when the session falls short.
 */

/** One factor: a password, a provider, an emailed link or code. */
export const ACR_SINGLE = "urn:noirly:acr:1fa";
/** Two factors, or a passkey that checked a PIN or fingerprint (something you have, and are or know). */
export const ACR_MFA = "urn:noirly:acr:mfa";
export const ACR_VALUES = [ACR_SINGLE, ACR_MFA] as const;

const AMR: Record<SignInMethod, string[]> = {
  password: ["pwd"],
  google: ["fed"],
  apple: ["fed"],
  microsoft: ["fed"],
  github: ["fed"],
  passkey: ["hwk", "user"],
  totp: ["otp"],
  recovery_code: ["otp"],
  magic_link: ["otp"],
  email_code: ["otp"],
  // The organization's IdP authenticated them; how strongly is its business.
  sso: ["fed"],
  // Approved from a browser that was already signed in: that session's methods carry over separately.
  mobile_browser: [],
};

/** Whether a set of sign-in methods reaches the multi-factor level. */
export function isMultiFactor(methods: readonly string[]): boolean {
  const unique = [...new Set(methods)];
  // A passkey alone checked the person (it's refused otherwise), so it is two factors in one.
  return unique.length >= 2 || (unique.length === 1 && unique[0] === "passkey");
}

export function acrFor(methods: readonly string[]): string {
  return isMultiFactor(methods) ? ACR_MFA : ACR_SINGLE;
}

export function amrFor(methods: readonly string[]): string[] {
  const values = new Set<string>();
  for (const method of methods) for (const value of AMR[method as SignInMethod] ?? []) values.add(value);
  if (isMultiFactor(methods)) values.add("mfa");
  return [...values];
}

/** Whether a session's level satisfies what an app asked for (`acr_values` is a preference list; mfa satisfies anything). */
export function satisfiesAcr(sessionAcr: string | null | undefined, requested: string[]): boolean {
  // Values Identity doesn't know are a wish, not a requirement (OIDC treats acr_values as voluntary).
  requested = requested.filter((value) => (ACR_VALUES as readonly string[]).includes(value));
  if (!requested.length) return true;
  if (sessionAcr === ACR_MFA) return true;
  return requested.includes(ACR_SINGLE) && sessionAcr === ACR_SINGLE;
}
