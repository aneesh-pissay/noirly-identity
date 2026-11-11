"use client";

/**
 * Solves the sign-up proof-of-work challenge in the browser: finds a
 * `solution` so SHA-256 of `challenge:solution` starts with `bits` zero bits.
 * About a second of work at the default difficulty.
 */
export async function solveSignupChallenge(challenge: string, bits: number): Promise<string> {
  const encoder = new TextEncoder();
  for (let n = 0; n < 50_000_000; n += 1) {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(`${challenge}:${n}`)));
    let zeros = 0;
    for (const byte of digest) {
      if (byte === 0) { zeros += 8; continue; }
      zeros += Math.clz32(byte) - 24;
      break;
    }
    if (zeros >= bits) return String(n);
  }
  throw new Error("Couldn't finish the sign-up check");
}
