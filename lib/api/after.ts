import { after } from "next/server";

/**
 * Runs work once the response is sent (Next's `after`). Outside a request
 * (tests, scripts) there's nothing to wait for, so it just starts the work and
 * lets it finish in the background. Errors are logged, never thrown.
 */
export function afterResponse(work: () => Promise<unknown>) {
  const safe = () => work().catch((error) => console.error("Background work failed", error instanceof Error ? error.message : "unknown error"));
  try {
    after(safe);
  } catch {
    void safe();
  }
}
