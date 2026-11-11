import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";
import { getEnv } from "@/lib/config/env";
import { createIdToken } from "@/lib/oidc/id-token";
import { getJwks, getSigningKeys, resetSigningKeyCache, retiredKeyRetentionSeconds, rotateSigningKeys } from "@/lib/oidc/keys";
import { openSecret, sealSecret } from "@/lib/security/encryption";
import { IdentityEvent } from "@/models/IdentityEvent";
import { SigningKey } from "@/models/SigningKey";
import { User } from "@/models/User";
import { createTestUser } from "./helpers";

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

async function idToken() {
  const { user } = await createTestUser({ email: `u${Math.random().toString(36).slice(2)}@example.com` });
  return createIdToken({ user: (await User.findById(user._id))!, clientId: "noirly-crm", scope: "openid", authTime: new Date() });
}

async function verifies(token: string) {
  resetSigningKeyCache();
  const jwks = createLocalJWKSet(await getJwks());
  return jwtVerify(token, jwks, { issuer: "http://localhost:3000", audience: "noirly-crm" }).then(() => true, () => false);
}

const kids = async () => (await getJwks()).keys.map((k) => k.kid);

/** The active key, as if it started signing `ago` ms before now. */
const ageActive = (ago: number) => SigningKey.updateOne({ state: "active" }, { $set: { activatedAt: new Date(Date.now() - ago) } });

describe("signing keys", () => {
  it("start from the configured key, kept sealed in the database", async () => {
    const token = await idToken();
    expect(decodeProtectedHeader(token).kid).toBe("test-key-1");
    expect(await kids()).toEqual(["test-key-1"]);
    const stored = await SigningKey.findOne({ kid: "test-key-1" }).select("+privateKeySealed").lean();
    expect(stored?.state).toBe("active");
    expect(stored?.privateKeySealed).not.toContain("PRIVATE KEY");
    // Sealed to its kid: it won't open as another key's.
    expect(openSecret(stored!.privateKeySealed, "signing-key:test-key-1")).toContain("PRIVATE KEY");
    expect(() => openSecret(stored!.privateKeySealed, "signing-key:someone-else")).toThrow();
    expect(openSecret(sealSecret("plain"))).toBe("plain");
  });

  it("roll over on schedule: publish ahead, switch when due, keep the old key until its tokens expire", async () => {
    const before = await idToken();
    const now = Date.now();

    // Not due yet: only the next key is published, signing nothing.
    const first = await rotateSigningKeys({ now: new Date(now) });
    expect(first.activated).toBeNull();
    expect(first.created).toHaveLength(1);
    const nextKid = first.created[0]!;
    resetSigningKeyCache();
    expect(await kids()).toEqual(["test-key-1", nextKid]);
    expect((await getSigningKeys()).kid).toBe("test-key-1");

    // Due, but the next key hasn't been out long enough for apps to have it.
    await ageActive(91 * DAY);
    expect((await rotateSigningKeys({ now: new Date(now + HOUR) })).activated).toBeNull();

    // Published long enough: it signs now; the old one is retired, still published.
    const switchAt = new Date(now + (getEnv().SIGNING_KEY_PREPUBLISH_HOURS + 1) * HOUR);
    const rolled = await rotateSigningKeys({ now: switchAt });
    expect(rolled).toMatchObject({ activated: nextKid, retired: ["test-key-1"], removed: [] });
    expect(rolled.created).toHaveLength(1);
    const after = await idToken();
    expect(decodeProtectedHeader(after).kid).toBe(nextKid);
    expect(await kids()).toEqual([nextKid, rolled.created[0], "test-key-1"]);
    expect(await verifies(before)).toBe(true);
    expect(await verifies(after)).toBe(true);
    const retired = await SigningKey.findOne({ kid: "test-key-1" }).lean();
    expect(retired?.removeAfter?.getTime()).toBe(switchAt.getTime() + retiredKeyRetentionSeconds() * 1000);

    // Nothing more is due straight after.
    expect(await rotateSigningKeys({ now: new Date(switchAt.getTime() + HOUR) })).toEqual({ created: [], activated: null, retired: [], removed: [] });

    // Once every token it signed has expired, the old key goes.
    const cleanup = await rotateSigningKeys({ now: new Date(retired!.removeAfter!.getTime() + 1000) });
    expect(cleanup.removed).toEqual(["test-key-1"]);
    expect(await kids()).not.toContain("test-key-1");
    expect(await IdentityEvent.countDocuments({ action: "signing_key.rotated", stream: "system" })).toBe(1);
    expect(await IdentityEvent.countDocuments({ action: "signing_key.removed" })).toBe(1);
  });

  it("rotate at once in an emergency, and can drop a leaked key so what it signed stops verifying", async () => {
    const leaked = await idToken();
    const { user: admin } = await createTestUser({ email: "admin@example.com" });

    const result = await rotateSigningKeys({ emergency: true, dropOld: true, actorId: String(admin._id) });
    expect(result.activated).toBeTruthy();
    expect(result.removed).toEqual(["test-key-1"]);
    expect(await kids()).not.toContain("test-key-1");
    expect(await verifies(leaked)).toBe(false);
    expect(decodeProtectedHeader(await idToken()).kid).toBe(result.activated);

    const event = await IdentityEvent.findOne({ action: "signing_key.rotated" }).lean();
    expect(event).toMatchObject({ stream: "admin", data: { from: "test-key-1", to: result.activated, emergency: true, droppedOld: true } });
    expect(String(event?.actorId)).toBe(String(admin._id));
  });

  it("rotates in an emergency without dropping: the old key retires as usual", async () => {
    const earlier = await idToken();
    const result = await rotateSigningKeys({ emergency: true });
    expect(result.retired).toEqual(["test-key-1"]);
    expect(await verifies(earlier)).toBe(true);
  });
});
