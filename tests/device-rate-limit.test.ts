import { describe, expect, it } from "vitest";
import { NextRequest } from "next/server";
import { ADDRESS_ATTEMPTS, DEVICE_ATTEMPTS, loginUser } from "@/lib/auth/auth-service";
import { requestMeta } from "@/lib/api/request";
import { deviceIdFrom } from "@/lib/security/device";
import { securePageResponse } from "@/lib/security/request";
import { createTestUser } from "./helpers";

const tryLogin = (email: string, meta: { ipAddress: string; deviceId: string | null }) =>
  loginUser({ email, password: "wrong-password-1A!" } as never, meta).then(() => "ok", (error: { code?: string }) => error.code ?? "error");

describe("device-aware rate limiting", () => {
  it("gives every browser a device id, and reads it (or a native app's header) back", () => {
    const response = securePageResponse(new NextRequest("http://localhost:3000/login"));
    const cookie = response.cookies.get("noirly_device");
    expect(cookie?.value).toMatch(/^[0-9a-f]{32}$/);
    expect(cookie?.httpOnly).toBe(true);
    // Already has one: left alone.
    expect(securePageResponse(new NextRequest("http://localhost:3000/login", { headers: { cookie: `noirly_device=${cookie!.value}` } })).cookies.get("noirly_device")).toBeUndefined();

    expect(deviceIdFrom(new Request("http://x", { headers: { cookie: `a=b; noirly_device=${cookie!.value}` } }))).toBe(cookie!.value);
    expect(deviceIdFrom(new Request("http://x", { headers: { "x-noirly-device": "mobile-device-0123456789" } }))).toBe("mobile-device-0123456789");
    expect(deviceIdFrom(new Request("http://x", { headers: { cookie: "noirly_device=<script>" } }))).toBeNull();
    expect(requestMeta(new Request("http://x", { headers: { "x-noirly-device": "mobile-device-0123456789" } })).deviceId).toBe("mobile-device-0123456789");
  });

  it("stops one device trying many accounts, even with every account under its own limit", async () => {
    await createTestUser({ email: "victim0@example.com" });
    const device = "stuffing-device-0000000001";
    const results: string[] = [];
    // One attempt per account, from different addresses: no account or address reaches its own limit.
    for (let i = 0; i < DEVICE_ATTEMPTS + 1; i += 1) results.push(await tryLogin(`victim${i}@example.com`, { ipAddress: `198.51.100.${i}`, deviceId: device }));
    expect(results.slice(0, DEVICE_ATTEMPTS).every((r) => r === "invalid_credentials")).toBe(true);
    expect(results.at(-1)).toBe("rate_limited");
    // Another device is unaffected.
    expect(await tryLogin("someone-else@example.com", { ipAddress: "203.0.113.50", deviceId: "another-device-0000000002" })).toBe("invalid_credentials");
  });

  it("stops one address trying many accounts, whatever device it claims", async () => {
    const results: string[] = [];
    for (let i = 0; i < ADDRESS_ATTEMPTS + 1; i += 1) results.push(await tryLogin(`nobody${i}@example.com`, { ipAddress: "192.0.2.77", deviceId: `rotating-device-${String(i).padStart(10, "0")}` }));
    expect(results.at(-1)).toBe("rate_limited");
  });
});
