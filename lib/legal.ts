import { getEnv } from "@/lib/config/env";

/**
 * Facts the privacy policy and account-deletion pages state. Change them here,
 * and bump `effectiveDate` whenever the policy's substance changes.
 */
export const LEGAL = {
  /** Who runs Noirly and is responsible for the data. */
  operator: "Aneesh Pissay",
  country: "India",
  effectiveDate: "10 October 2026",
  host: "noirly.identity.aneesh-pissay.in",
  /** Noirly apps that sign in with Identity, each with its own privacy policy. */
  apps: [
    { name: "Noirly Flow", what: "tasks, boards and workspaces", privacyUrl: "https://noirly.flow.aneesh-pissay.in/privacy" },
  ],
} as const;

/**
 * Where privacy requests go: PRIVACY_CONTACT_EMAIL, else the address account
 * emails are sent from (EMAIL_FROM), else null (pages then point to the
 * deletion page only).
 */
export function privacyContactEmail(): string | null {
  const env = getEnv();
  if (env.PRIVACY_CONTACT_EMAIL) return env.PRIVACY_CONTACT_EMAIL;
  const from = env.EMAIL_FROM?.match(/<([^>]+)>/)?.[1] ?? env.EMAIL_FROM;
  return from && /^[^\s@]+@[^\s@]+$/.test(from.trim()) ? from.trim() : null;
}
