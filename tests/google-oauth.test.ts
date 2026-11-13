import { describe, expect, it } from "vitest";
import { loginWithGoogleProfile } from "@/lib/auth/google";
import { loginWithProviderProfile, providerSignInOffUrl } from "@/lib/auth/provider-login";
import { LinkedAccount } from "@/models/LinkedAccount";
import { User } from "@/models/User";
import { createTestUser } from "./helpers";
import { readOAuthState, safeReturnTo, signOAuthState } from "@/lib/auth/oauth-state";

function googleProfile(overrides?: Partial<Parameters<typeof loginWithGoogleProfile>[0]>) {
  return {
    sub: "google-sub-123",
    email: "google.user@example.com",
    emailVerified: true,
    firstName: "Gita",
    lastName: "User",
    displayName: "Gita User",
    avatarUrl: "https://example.com/a.png",
    ...overrides,
  };
}

describe("providers never sign in", () => {
  it("won't make an account from a Google profile", async () => {
    await expect(loginWithGoogleProfile(googleProfile(), { ipAddress: "1.1.1.1" })).rejects.toMatchObject({ code: "provider_sign_in_off", status: 403 });
    expect(await User.countDocuments()).toBe(0);
    expect(await LinkedAccount.countDocuments()).toBe(0);
  });

  it("won't sign in to, or link, an existing account that has the same address", async () => {
    await createTestUser({ email: "existing@example.com" });
    await expect(loginWithGoogleProfile(googleProfile({ email: "existing@example.com", sub: "google-existing" }), {})).rejects.toMatchObject({ code: "provider_sign_in_off" });
    expect(await LinkedAccount.countDocuments()).toBe(0);
  });

  it("won't sign in with a linked account either, for any provider", async () => {
    const { user } = await createTestUser({ email: "linked@example.com" });
    for (const provider of ["google", "apple", "microsoft", "github"] as const) {
      await LinkedAccount.create({ userId: user._id, provider, providerAccountId: `${provider}-linked` });
      await expect(loginWithProviderProfile(provider, googleProfile({ email: "linked@example.com", sub: `${provider}-linked` }), {})).rejects.toMatchObject({ code: "provider_sign_in_off" });
    }
  });

  it("sends an old provider button back to the sign-in page, saying why", () => {
    const url = providerSignInOffUrl("github", "https://id.example.com");
    expect(url.pathname).toBe("/login");
    expect(url.searchParams.get("error")).toContain("doesn't sign in with GitHub");
  });
});

describe("oauth state", () => {
  it("round-trips signed state", () => {
    const signed = signOAuthState({
      state: "abc",
      codeVerifier: "verifier-value-here",
      returnTo: "/api/oauth/authorize?x=1",
      nonce: "n",
      exp: Date.now() + 60_000,
    });
    const read = readOAuthState(signed);
    expect(read?.state).toBe("abc");
    expect(read?.returnTo).toBe("/api/oauth/authorize?x=1");
  });

  it("rejects tampered state", () => {
    const signed = signOAuthState({
      state: "abc",
      codeVerifier: "verifier-value-here",
      returnTo: "/",
      nonce: "n",
      exp: Date.now() + 60_000,
    });
    const [body, sig] = signed.split(".");
    expect(readOAuthState(`${body}tamper.${sig}`)).toBeNull();
    expect(readOAuthState(`${body}.${sig.slice(0, -2)}aa`)).toBeNull();
  });

  it("blocks open redirects", () => {
    expect(safeReturnTo("https://evil.example/phish", "http://localhost:3000")).toBe("/");
    expect(safeReturnTo("/login", "http://localhost:3000")).toBe("/login");
    expect(
      safeReturnTo("http://localhost:3000/api/oauth/authorize?x=1", "http://localhost:3000"),
    ).toBe("/api/oauth/authorize?x=1");
  });
});
