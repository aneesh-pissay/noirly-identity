import { generateKeyPairSync } from "node:crypto";
import { createLocalJWKSet, exportJWK, SignJWT } from "jose";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { linkProvider } from "@/lib/account/identities";
import {
  buildAuthorizationUrl,
  githubProfileFrom,
  isRedirectProvider,
  MICROSOFT_CONSUMER_TENANT,
  microsoftProfileFromIdToken,
  setMicrosoftKeysForTests,
} from "@/lib/auth/oauth-providers";
import { loginWithProviderProfile, type ProviderProfile } from "@/lib/auth/provider-login";
import { resetEnvCache } from "@/lib/config/env";
import { LinkedAccount } from "@/models/LinkedAccount";
import { User } from "@/models/User";
import { createTestUser } from "./helpers";

const microsoft = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const KEYS = ["MICROSOFT_CLIENT_ID", "MICROSOFT_CLIENT_SECRET", "MICROSOFT_TENANT", "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET"] as const;
const WORK_TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47";

beforeEach(async () => {
  process.env.MICROSOFT_CLIENT_ID = "ms-client";
  process.env.MICROSOFT_CLIENT_SECRET = "ms-secret";
  process.env.GITHUB_CLIENT_ID = "gh-client";
  process.env.GITHUB_CLIENT_SECRET = "gh-secret";
  resetEnvCache();
  setMicrosoftKeysForTests(createLocalJWKSet({ keys: [{ ...(await exportJWK(microsoft.publicKey)), kid: "ms-1", alg: "ES256" }] }));
});

afterEach(() => {
  for (const key of KEYS) delete process.env[key];
  resetEnvCache();
  setMicrosoftKeysForTests(null);
});

function msToken(claims: Record<string, unknown>, tid = MICROSOFT_CONSUMER_TENANT) {
  return new SignJWT({ tid, nonce: "n", name: "Asha Rao", email: "asha@outlook.com", ...claims })
    .setProtectedHeader({ alg: "ES256", kid: "ms-1" })
    .setIssuer(String(claims.iss ?? `https://login.microsoftonline.com/${tid}/v2.0`))
    .setAudience("ms-client")
    .setSubject("ms-sub")
    .setIssuedAt()
    .setExpirationTime("10m")
    .sign(microsoft.privateKey);
}

describe("Microsoft and GitHub", () => {
  it("send people there with PKCE, and only for the providers this route serves", () => {
    const ms = new URL(buildAuthorizationUrl("microsoft", { state: "s", nonce: "n", codeChallenge: "c" }));
    expect(ms.origin + ms.pathname).toBe("https://login.microsoftonline.com/common/oauth2/v2.0/authorize");
    expect(Object.fromEntries(ms.searchParams)).toMatchObject({ client_id: "ms-client", response_type: "code", scope: "openid email profile", nonce: "n", code_challenge: "c", code_challenge_method: "S256", redirect_uri: "http://localhost:3000/api/auth/oauth/microsoft/callback" });
    const gh = new URL(buildAuthorizationUrl("github", { state: "s", nonce: "n", codeChallenge: "c" }));
    expect(gh.origin + gh.pathname).toBe("https://github.com/login/oauth/authorize");
    expect(Object.fromEntries(gh.searchParams)).toMatchObject({ client_id: "gh-client", scope: "read:user user:email", code_challenge: "c" });
    expect(isRedirectProvider("github")).toBe(true);
    expect(isRedirectProvider("google")).toBe(false);
  });

  it("trust a Microsoft address for personal accounts, and for work accounts only when Microsoft verified the domain", async () => {
    expect(await microsoftProfileFromIdToken(await msToken({}), "n")).toMatchObject({ sub: `${MICROSOFT_CONSUMER_TENANT}:ms-sub`, email: "asha@outlook.com", emailVerified: true, firstName: "Asha", lastName: "Rao" });
    expect(await microsoftProfileFromIdToken(await msToken({ email: "asha@contoso.com" }, WORK_TENANT), "n")).toMatchObject({ email: "asha@contoso.com", emailVerified: false });
    expect(await microsoftProfileFromIdToken(await msToken({ email: "asha@contoso.com", xms_edov: true }, WORK_TENANT), "n")).toMatchObject({ emailVerified: true });
    // Wrong nonce, or an issuer that doesn't match the tenant.
    await expect(microsoftProfileFromIdToken(await msToken({}), "other")).rejects.toMatchObject({ code: "microsoft_auth_failed" });
    await expect(microsoftProfileFromIdToken(await msToken({ iss: "https://login.microsoftonline.com/someone-else/v2.0" }), "n")).rejects.toMatchObject({ code: "microsoft_auth_failed" });
  });

  it("take GitHub's primary address, verified or not", () => {
    expect(githubProfileFrom({ id: 42, login: "asha", name: "Asha Rao", avatar_url: "https://avatars.example/42" }, [{ email: "old@example.com", verified: true }, { email: "Asha@Example.com", primary: true, verified: true }])).toEqual({
      sub: "42", email: "asha@example.com", emailVerified: true, firstName: "Asha", lastName: "Rao", displayName: "Asha Rao", avatarUrl: "https://avatars.example/42",
    });
    expect(githubProfileFrom({ id: 7, login: "nobody" }, [{ email: "n@example.com", primary: true, verified: false }])).toMatchObject({ emailVerified: false, displayName: "nobody" });
    expect(() => githubProfileFrom({ id: 7 }, [])).toThrow("didn't share an email");
  });
});

describe("unverified provider addresses", () => {
  const unverified = (sub: string, email: string): ProviderProfile => ({ sub, email, emailVerified: false, firstName: "A", lastName: "R", displayName: "A R", avatarUrl: null });

  it("can't find or create an account, but a linked one still signs in", async () => {
    const { user } = await createTestUser({ email: "asha@contoso.com" });
    // Someone's organisation claims the address: no takeover, no new account.
    await expect(loginWithProviderProfile("microsoft", unverified("t:1", "asha@contoso.com"), {})).rejects.toMatchObject({ code: "microsoft_email_unverified" });
    await expect(loginWithProviderProfile("github", unverified("99", "new@example.com"), {})).rejects.toMatchObject({ code: "github_email_unverified" });
    expect(await User.countDocuments()).toBe(1);
    expect(await LinkedAccount.countDocuments()).toBe(0);

    // Linked from settings, where the email isn't relied on, it signs in by its id.
    await linkProvider("microsoft", String(user._id), unverified("t:1", "asha@contoso.com"));
    const signedIn = await loginWithProviderProfile("microsoft", unverified("t:1", "asha@contoso.com"), {});
    expect(signedIn.user.id).toBe(String(user._id));
  });

  it("never marks the account's own address verified on another address's say-so", async () => {
    const { user } = await createTestUser({ email: "pending@example.com", status: "pending_verification" });
    await linkProvider("github", String(user._id), { sub: "5", email: "other@example.com", emailVerified: true, firstName: "A", lastName: "R", displayName: "A R", avatarUrl: null });
    await expect(loginWithProviderProfile("github", { sub: "5", email: "other@example.com", emailVerified: true, firstName: "A", lastName: "R", displayName: "A R", avatarUrl: null }, {})).rejects.toMatchObject({ code: "email_not_verified" });
    expect((await User.findById(user._id).lean())!.emailVerified).toBe(false);
  });
});
