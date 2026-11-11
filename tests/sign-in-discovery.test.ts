import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { discoverSignIn } from "@/lib/auth/discovery";
import { resetEnvCache } from "@/lib/config/env";
import { LinkedAccount } from "@/models/LinkedAccount";
import { Passkey } from "@/models/SecurityCredential";
import { User } from "@/models/User";
import { createTestUser } from "./helpers";

beforeEach(() => {
  process.env.GOOGLE_CLIENT_ID = "google-client";
  process.env.GOOGLE_CLIENT_SECRET = "google-secret";
  resetEnvCache();
});

afterEach(() => {
  delete process.env.GOOGLE_CLIENT_ID;
  delete process.env.GOOGLE_CLIENT_SECRET;
  resetEnvCache();
});

async function passwordlessUser(email: string) {
  return User.create({ email, passwordHash: null, firstName: "N", lastName: "P", displayName: "N P", emailVerified: true, status: "active" });
}

const ORDINARY = { password: true, passkey: false, providers: [], emailLink: true };

describe("email-first sign-in", () => {
  it("answers an unknown address exactly as it answers a password account", async () => {
    const { user } = await createTestUser({ email: "has-password@example.com" });
    await LinkedAccount.create({ userId: user._id, provider: "google", providerAccountId: "g-1" });
    await Passkey.create({ userId: user._id, credentialId: "k-1", publicKey: "k", counter: 0 });
    const known = await discoverSignIn("Has-Password@example.com");
    const unknown = await discoverSignIn("nobody@example.com");
    expect(known).toEqual({ email: "has-password@example.com", ...ORDINARY });
    expect(unknown).toEqual({ email: "nobody@example.com", ...ORDINARY });
  });

  it("steers accounts without a password to what they can use", async () => {
    const googleOnly = await passwordlessUser("google-only@example.com");
    await LinkedAccount.create({ userId: googleOnly._id, provider: "google", providerAccountId: "g-2" });
    expect(await discoverSignIn("google-only@example.com")).toEqual({ email: "google-only@example.com", password: false, passkey: false, providers: ["google"], emailLink: true });

    const passkeyOnly = await passwordlessUser("passkey-only@example.com");
    await Passkey.create({ userId: passkeyOnly._id, credentialId: "k-2", publicKey: "k", counter: 0 });
    expect(await discoverSignIn("passkey-only@example.com")).toMatchObject({ password: false, passkey: true, providers: [] });
  });

  it("doesn't offer a provider that isn't set up here, and falls back to a password box", async () => {
    const appleOnly = await passwordlessUser("apple-only@example.com");
    await LinkedAccount.create({ userId: appleOnly._id, provider: "apple", providerAccountId: "a-1" });
    expect(await discoverSignIn("apple-only@example.com")).toMatchObject({ password: true, providers: [] });
  });

  it("gives everyone the ordinary answer once an address has been looked up too often", async () => {
    const googleOnly = await passwordlessUser("busy@example.com");
    await LinkedAccount.create({ userId: googleOnly._id, provider: "google", providerAccountId: "g-3" });
    for (let i = 0; i < 10; i++) await discoverSignIn("busy@example.com");
    expect(await discoverSignIn("busy@example.com")).toEqual({ email: "busy@example.com", ...ORDINARY });
  });
});
