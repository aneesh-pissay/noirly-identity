/**
 * The ways an account signs in, as settings show them. Shared by the server
 * (lib/account/identities.ts) and the account page, so it holds no server code.
 */

export const PROVIDERS = ["google", "apple", "microsoft", "github"] as const;

export const PROVIDER_LABEL: Record<(typeof PROVIDERS)[number], string> = { google: "Google", apple: "Apple", microsoft: "Microsoft", github: "GitHub" };

/** Where signing in (or, with `intent=link`, linking) with a provider starts. */
export function providerStartPath(provider: (typeof PROVIDERS)[number]) {
  return provider === "google" || provider === "apple" ? `/api/auth/${provider}` : `/api/auth/oauth/${provider}`;
}
export type Provider = (typeof PROVIDERS)[number];

export type SignInMethods = {
  password: boolean;
  passkeys: number;
  providers: Array<{ provider: Provider; available: boolean; linked: { email: string | null; linkedAt: string } | null }>;
};

export type MethodCounts = { password: boolean; passkeys: number; providers: number };

/** How many separate ways in an account has; a passkey counts once however many there are. */
export function methodCount(counts: MethodCounts) {
  return (counts.password ? 1 : 0) + (counts.passkeys > 0 ? 1 : 0) + counts.providers;
}
