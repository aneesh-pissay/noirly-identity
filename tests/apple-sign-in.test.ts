import { createHash, generateKeyPairSync } from "node:crypto";
import { createLocalJWKSet, exportJWK, importSPKI, jwtVerify, SignJWT } from "jose";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { linkProvider } from "@/lib/account/identities";
import {
  appleClientSecret,
  buildAppleAuthorizationUrl,
  loginWithAppleProfile,
  parseAppleUser,
  setAppleKeysForTests,
  verifyAppleIdToken,
} from "@/lib/auth/apple";
import { resetEnvCache } from "@/lib/config/env";
import { LinkedAccount } from "@/models/LinkedAccount";
import { User } from "@/models/User";
import { createTestUser } from "./helpers";

// Apple's side: a key it signs id_tokens with, published as a key set.
const apple = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
// The team's Sign in with Apple key (.p8), which signs Identity's client secret.
const team = generateKeyPairSync("ec", { namedCurve: "prime256v1", privateKeyEncoding: { type: "pkcs8", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });

const KEYS = ["APPLE_CLIENT_ID", "APPLE_TEAM_ID", "APPLE_KEY_ID", "APPLE_PRIVATE_KEY", "APPLE_MOBILE_CLIENT_IDS"] as const;

beforeEach(async () => {
  process.env.APPLE_CLIENT_ID = "com.noirly.identity.web";
  process.env.APPLE_TEAM_ID = "TEAM123456";
  process.env.APPLE_KEY_ID = "KEY1234567";
  process.env.APPLE_PRIVATE_KEY = team.privateKey.replace(/\n/g, "\\n");
  process.env.APPLE_MOBILE_CLIENT_IDS = "com.noirly.flow";
  resetEnvCache();
  const jwk = { ...(await exportJWK(apple.publicKey)), kid: "apple-1", alg: "ES256" };
  setAppleKeysForTests(createLocalJWKSet({ keys: [jwk] }));
});

afterEach(() => {
  for (const key of KEYS) delete process.env[key];
  resetEnvCache();
  setAppleKeysForTests(null);
});

/** An id_token as Apple would sign it. */
function appleToken(claims: Record<string, unknown>, audience = "com.noirly.identity.web") {
  return new SignJWT({ email: "rel4y@privaterelay.appleid.com", email_verified: "true", ...claims })
    .setProtectedHeader({ alg: "ES256", kid: "apple-1" })
    .setIssuer("https://appleid.apple.com")
    .setAudience(audience)
    .setSubject(String(claims.sub ?? "001234.apple-user"))
    .setIssuedAt()
    .setExpirationTime("10m")
    .sign(apple.privateKey);
}

describe("Sign in with Apple", () => {
  it("asks Apple to post back with name and email, and signs a client secret with the team key", async () => {
    const url = new URL(buildAppleAuthorizationUrl({ state: "st", nonce: "nn" }));
    expect(url.origin + url.pathname).toBe("https://appleid.apple.com/auth/authorize");
    expect(Object.fromEntries(url.searchParams)).toMatchObject({ client_id: "com.noirly.identity.web", response_mode: "form_post", scope: "name email", state: "st", nonce: "nn", redirect_uri: "http://localhost:3000/api/auth/apple/callback" });

    const secret = await appleClientSecret();
    const { payload, protectedHeader } = await jwtVerify(secret, await importSPKI(team.publicKey, "ES256"), { issuer: "TEAM123456", audience: "https://appleid.apple.com" });
    expect(protectedHeader).toMatchObject({ alg: "ES256", kid: "KEY1234567" });
    expect(payload.sub).toBe("com.noirly.identity.web");
  });

  it("checks Apple's id_token: signature, audience and nonce (raw on the web, hashed from apps)", async () => {
    const profile = await verifyAppleIdToken({ idToken: await appleToken({ nonce: "web-nonce" }), nonce: "web-nonce", name: { firstName: "Asha", lastName: "Rao" } });
    expect(profile).toMatchObject({ sub: "001234.apple-user", email: "rel4y@privaterelay.appleid.com", emailVerified: true, displayName: "Asha Rao" });

    const hashed = createHash("sha256").update("app-nonce").digest("hex");
    await expect(verifyAppleIdToken({ idToken: await appleToken({ nonce: hashed }, "com.noirly.flow"), nonce: "app-nonce", native: true })).resolves.toMatchObject({ sub: "001234.apple-user" });
    // An app's token isn't good on the web, and a wrong nonce isn't good anywhere.
    await expect(verifyAppleIdToken({ idToken: await appleToken({ nonce: hashed }, "com.noirly.flow"), nonce: "app-nonce" })).rejects.toMatchObject({ code: "apple_auth_failed" });
    await expect(verifyAppleIdToken({ idToken: await appleToken({ nonce: "other" }), nonce: "web-nonce" })).rejects.toMatchObject({ code: "apple_auth_failed" });
    // Signed by someone else.
    const stranger = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const forged = await new SignJWT({ email: "x@example.com", email_verified: true }).setProtectedHeader({ alg: "ES256", kid: "apple-1" }).setIssuer("https://appleid.apple.com").setAudience("com.noirly.identity.web").setSubject("s").setIssuedAt().setExpirationTime("10m").sign(stranger.privateKey);
    await expect(verifyAppleIdToken({ idToken: forged })).rejects.toMatchObject({ code: "apple_auth_failed" });
  });

  it("reads the name Apple sends once, and nothing harmful from it", () => {
    expect(parseAppleUser('{"name":{"firstName":"Asha","lastName":"Rao"},"email":"a@b.c"}')).toEqual({ firstName: "Asha", lastName: "Rao" });
    expect(parseAppleUser("not json")).toEqual({});
    expect(parseAppleUser(null)).toEqual({});
  });

  it("never signs in or makes an account, even with a checked Apple token", async () => {
    const profile = await verifyAppleIdToken({ idToken: await appleToken({ nonce: "n" }), nonce: "n", name: { firstName: "Asha", lastName: "Rao" } });
    await expect(loginWithAppleProfile(profile, { ipAddress: "203.0.113.7" })).rejects.toMatchObject({ code: "provider_sign_in_off" });
    expect(await User.countDocuments()).toBe(0);
  });

  it("links from settings, alongside Google", async () => {
    const { user } = await createTestUser();
    await linkProvider("google", String(user._id), { sub: "g-1", email: "g@gmail.com", emailVerified: true, firstName: "A", lastName: "B", displayName: "A B", avatarUrl: null });
    await linkProvider("apple", String(user._id), { sub: "a-1", email: "rel@privaterelay.appleid.com", emailVerified: true, firstName: "A", lastName: "B", displayName: "A B", avatarUrl: null });
    expect((await LinkedAccount.find({ userId: user._id }).lean()).map((l) => l.provider).sort()).toEqual(["apple", "google"]);
    await expect(linkProvider("apple", String(user._id), { sub: "a-2", email: "x@y.z", emailVerified: true, firstName: "A", lastName: "B", displayName: "A B", avatarUrl: null })).rejects.toMatchObject({ code: "already_linked" });
  });
});
