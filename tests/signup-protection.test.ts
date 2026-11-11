import { createHash } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { POST as registerRoute } from "@/app/api/auth/register/route";
import { registerUser } from "@/lib/auth/auth-service";
import { getEnv } from "@/lib/config/env";
import { checkSignupAllowed, isDisposableEmail, issueSignupChallenge, leadingZeroBits, SIGNUPS_PER_ADDRESS, SIGNUPS_PER_DEVICE, verifySignupChallenge } from "@/lib/security/signup-protection";

const jar = vi.hoisted(() => new Map<string, string>());
vi.mock("next/headers", () => ({ cookies: async () => ({ get: (key: string) => (jar.has(key) ? { value: jar.get(key) } : undefined) }) }));
beforeEach(() => { jar.clear(); jar.set(getEnv().CSRF_COOKIE_NAME, "csrf"); });

function solve(challenge: string, bits: number) {
  for (let n = 0; ; n += 1) {
    if (leadingZeroBits(createHash("sha256").update(`${challenge}:${n}`).digest()) >= bits) return String(n);
  }
}

const person = (email: string) => ({ email, password: "A-good-password-9!", firstName: "New", lastName: "Person" });

describe("sign-up proof of work", () => {
  it("is solved once, and not reused, forged or skipped", async () => {
    const { challenge, bits } = issueSignupChallenge();
    const solution = solve(challenge, bits);
    await verifySignupChallenge(challenge, solution);
    await expect(verifySignupChallenge(challenge, solution)).rejects.toMatchObject({ code: "challenge_failed" });

    const fresh = issueSignupChallenge();
    const [nonce, exp, , sig] = fresh.challenge.split(".");
    // Lowering the difficulty breaks the signature.
    await expect(verifySignupChallenge(`${nonce}.${exp}.0.${sig}`, "0")).rejects.toMatchObject({ code: "challenge_failed" });
    await expect(verifySignupChallenge(undefined, undefined)).rejects.toMatchObject({ code: "challenge_failed" });
    // Expired.
    const old = issueSignupChallenge(Date.now() - 3600_000);
    await expect(verifySignupChallenge(old.challenge, solve(old.challenge, old.bits))).rejects.toMatchObject({ code: "challenge_failed" });
  });

  it("is required by the web sign-up form", async () => {
    const post = (body: unknown) => registerRoute(new NextRequest("http://localhost:3000/api/auth/register", { method: "POST", headers: { "content-type": "application/json", "x-csrf-token": "csrf", origin: "http://localhost:3000" }, body: JSON.stringify(body) }));
    expect((await post(person("skip@example.com"))).status).toBe(400);
    const { challenge, bits } = issueSignupChallenge();
    expect((await post({ ...person("solved@example.com"), challenge, solution: solve(challenge, bits) })).status).toBe(201);
  });
});

describe("disposable addresses and velocity", () => {
  it("refuse throwaway inboxes, subdomains included, and configured extras", async () => {
    expect(isDisposableEmail("x@mailinator.com")).toBe(true);
    expect(isDisposableEmail("x@inbox.mailinator.com")).toBe(true);
    expect(isDisposableEmail("x@example.com")).toBe(false);
    process.env.DISPOSABLE_EMAIL_DOMAINS = "junk.example";
    expect(isDisposableEmail("x@junk.example")).toBe(true);
    delete process.env.DISPOSABLE_EMAIL_DOMAINS;
    await expect(registerUser(person("x@yopmail.com") as never, {})).rejects.toMatchObject({ code: "disposable_email" });
  });

  it("limit new accounts per address and per device each hour", async () => {
    for (let i = 0; i < SIGNUPS_PER_DEVICE; i += 1) await checkSignupAllowed(`d${i}@example.com`, { ipAddress: `198.51.100.${i}`, deviceId: "signup-device-00000001" });
    await expect(checkSignupAllowed("d9@example.com", { ipAddress: "198.51.100.99", deviceId: "signup-device-00000001" })).rejects.toMatchObject({ code: "rate_limited" });
    for (let i = 0; i < SIGNUPS_PER_ADDRESS; i += 1) await checkSignupAllowed(`a${i}@example.com`, { ipAddress: "192.0.2.10", deviceId: `dev-${String(i).padStart(16, "0")}` });
    await expect(checkSignupAllowed("a9@example.com", { ipAddress: "192.0.2.10", deviceId: "dev-9999999999999999" })).rejects.toMatchObject({ code: "rate_limited" });
  });
});
