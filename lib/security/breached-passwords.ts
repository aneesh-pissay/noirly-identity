import { createHash } from "node:crypto";
import { AppError } from "@/lib/api/errors";
import { getEnv } from "@/lib/config/env";

/**
 * Compromised password checks against the Have I Been Pwned corpus, by
 * k-anonymity: only the first five characters of the password's SHA-1 leave
 * Identity (and responses are padded), so neither the password nor its hash
 * is ever shared. A password found in breaches is refused when it's chosen
 * (sign-up, change, reset, adding one); one found at sign-in still signs the
 * person in, but flags the account and tells them to change it.
 *
 * If the lookup can't be made (network down, slow), the check passes:
 * availability of sign-in matters more than this one signal.
 */

type RangeFetcher = (prefix: string) => Promise<string>;

async function fetchRange(prefix: string): Promise<string> {
  const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { "Add-Padding": "true", "User-Agent": "noirly-identity" },
    signal: AbortSignal.timeout(2500),
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.text();
}

let fetcher: RangeFetcher | null = null;
/** Tests: answer range lookups without the network (null restores the default). */
export function setBreachRangeFetcher(next: RangeFetcher | null) {
  fetcher = next;
}

function enabled() {
  // Off in tests unless a fetcher is set; set BREACHED_PASSWORD_CHECK=off to disable anywhere.
  if (fetcher) return true;
  return getEnv().NODE_ENV !== "test" && process.env.BREACHED_PASSWORD_CHECK !== "off";
}

/** How many breaches the password has been seen in (0 when none, or when it couldn't be checked). */
export async function breachCount(password: string): Promise<number> {
  if (!enabled()) return 0;
  const hash = createHash("sha1").update(password).digest("hex").toUpperCase();
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  try {
    const body = await (fetcher ?? fetchRange)(prefix);
    for (const line of body.split(/\r?\n/)) {
      const [candidate, count] = line.trim().split(":");
      if (candidate === suffix) return Number(count) || 0;
    }
    return 0;
  } catch (error) {
    console.warn("Breached password check unavailable:", error instanceof Error ? error.message : "unknown error");
    return 0;
  }
}

/** For a password being chosen: refuse one known from breaches. */
export async function assertNotBreached(password: string) {
  if ((await breachCount(password)) > 0) {
    throw new AppError("That password has appeared in a data breach, so it isn't safe to use. Choose another.", 400, "breached_password");
  }
}
