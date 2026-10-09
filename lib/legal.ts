import { getEnv } from "@/lib/config/env";

/**
 * Facts the privacy policy and account-deletion pages state. Change them here,
 * and bump `effectiveDate` whenever the policy's substance changes.
 */
export const LEGAL = {
  /** Who runs Noirly and is responsible for the data. */
  operator: "Aneesh Pissay",
  country: "India",
  effectiveDate: "9 October 2026",
  /** Apps this policy covers, with the host each runs on. */
  products: [
    { name: "Noirly Identity", what: "accounts and sign-in for every Noirly app", host: "noirly.identity.aneesh-pissay.in" },
    { name: "Noirly Flow", what: "tasks, boards and workspaces, on the web and on Android", host: "noirly.flow.aneesh-pissay.in" },
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
