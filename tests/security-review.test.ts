import { describe, expect, it } from "vitest";
import { sameOriginPath, sanitizeReturnTo } from "@/lib/auth/return-to";
import { safeReturnTo } from "@/lib/auth/oauth-state";
import { resolveOneTapReturnTo } from "@/lib/auth/one-tap-return";
import { loginWithGoogleProfile } from "@/lib/auth/google";
import { changeUserPassword, loginUser, registerUser } from "@/lib/auth/auth-service";
import { createAuthorizationCode } from "@/lib/oauth/authorize";
import { exchangeAuthorizationCode, exchangeRefreshToken } from "@/lib/oauth/token";
import { buildUserInfo } from "@/lib/oidc/userinfo";
import { issueAccessToken, issueRefreshToken, resolveAccessToken } from "@/lib/tokens/token-service";
import { generateSecureToken } from "@/lib/security/crypto";
import { validateSession } from "@/lib/sessions/session-service";
import { AccessToken } from "@/models/AccessToken";
import { RefreshToken } from "@/models/RefreshToken";
import { LinkedAccount } from "@/models/LinkedAccount";
import { Mfa, Passkey } from "@/models/SecurityCredential";
import { User } from "@/models/User";
import { createAuthedSession, createTestClient, createTestUser, pkceChallenge } from "./helpers";

const ORIGIN = "https://id.example";

describe("return_to can't leave Identity", () => {
  // Browsers strip tabs/newlines and treat "\" as "/", so these look like
  // paths but navigate to evil.example.
  const tricks = ["/\t/evil.example", "/\n/evil.example/x", "/\r\n/evil.example", "/\\evil.example", "\\\\evil.example", "//evil.example"];

  it("rejects paths a browser would turn into another site", () => {
    for (const trick of tricks) {
      expect(sameOriginPath(trick, ORIGIN), JSON.stringify(trick)).toBeNull();
      expect(sanitizeReturnTo(trick, ORIGIN), JSON.stringify(trick)).toBeNull();
      expect(sanitizeReturnTo(trick), JSON.stringify(trick)).toBeNull();
      expect(safeReturnTo(trick, ORIGIN), JSON.stringify(trick)).toBe("/");
    }
  });

  it("still keeps genuine paths and same-origin URLs", () => {
    expect(sanitizeReturnTo("/api/oauth/authorize?client_id=x&state=y", ORIGIN)).toBe("/api/oauth/authorize?client_id=x&state=y");
    expect(sanitizeReturnTo(`${ORIGIN}/account#top`, ORIGIN)).toBe("/account#top");
    expect(safeReturnTo("/mobile-login?request=abc", ORIGIN)).toBe("/mobile-login?request=abc");
  });

  it("One Tap's return_to falls back for the same tricks", async () => {
    for (const trick of tricks.filter((t) => t.startsWith("/"))) {
      const resolved = await resolveOneTapReturnTo(trick);
      expect(new URL(resolved).origin, JSON.stringify(trick)).toBe(new URL(process.env.APP_URL!).origin);
    }
  });
});

describe("Google sign-in can't be pre-hijacked", () => {
  it("drops everything an unverified registrant set up before linking", async () => {
    // An attacker registers the victim's address (never verifies it) and
    // adds their own second factors.
    const { user: squatter, password } = await createTestUser({ email: "victim@example.com", status: "pending_verification" });
    const { token: attackerSession } = await createAuthedSession(String(squatter._id));
    await Mfa.create({ userId: squatter._id, enabled: true, secret: "x" });
    await Passkey.create({ userId: squatter._id, credentialId: "attacker-key", publicKey: "k", counter: 0 });
    await LinkedAccount.create({ userId: squatter._id, provider: "google", providerAccountId: "attacker-google" });

    // The real owner signs in with Google.
    const result = await loginWithGoogleProfile({
      sub: "victim-google", email: "victim@example.com", emailVerified: true,
      firstName: "Real", lastName: "Owner", displayName: "Real Owner", avatarUrl: null,
    }, {});
    expect(result.user.id).toBe(String(squatter._id));
    expect(result.user.emailVerified).toBe(true);

    const stored = await User.findById(squatter._id).select("+passwordHash");
    expect(stored?.passwordHash).toBeFalsy();
    expect(await Mfa.exists({ userId: squatter._id })).toBeNull();
    expect(await Passkey.exists({ userId: squatter._id })).toBeNull();
    expect(await LinkedAccount.exists({ providerAccountId: "attacker-google" })).toBeNull();
    expect(await LinkedAccount.exists({ providerAccountId: "victim-google" })).toBeTruthy();
    expect(await validateSession(attackerSession)).toBeNull();

    // The attacker's password no longer opens the account.
    await expect(loginUser({ email: "victim@example.com", password }, { ipAddress: "9.9.9.9" }))
      .rejects.toMatchObject({ code: "invalid_credentials" });
  });

  it("leaves a verified account's password alone when Google links", async () => {
    const { user, password } = await createTestUser({ email: "owner@example.com" });
    await loginWithGoogleProfile({
      sub: "owner-google", email: "owner@example.com", emailVerified: true,
      firstName: "O", lastName: "W", displayName: "O W", avatarUrl: null,
    }, {});
    const result = await loginUser({ email: "owner@example.com", password }, { ipAddress: "8.8.8.8" });
    expect(result.user.id).toBe(String(user._id));
  });
});

describe("unverified accounts get nothing apps would trust", () => {
  it("no authorization code, and no userinfo for an existing token", async () => {
    const registered = await registerUser(
      { email: "squat@example.com", password: "StrongPass1!", firstName: "S", lastName: "Q" },
      {},
    );
    const { client } = await createTestClient();
    await expect(createAuthorizationCode({
      sessionToken: registered.sessionToken,
      clientId: client.clientId,
      redirectUri: client.redirectUris[0]!,
      scope: "openid profile email",
      codeChallenge: pkceChallenge(generateSecureToken(32)),
      codeChallengeMethod: "S256",
    })).rejects.toMatchObject({ code: "email_not_verified" });

    // A token minted before this check existed stops working too.
    const session = await validateSession(registered.sessionToken);
    const { token } = await issueAccessToken({
      clientId: client.clientId, userId: registered.user.id, sessionId: session!.session._id, scope: "openid email",
    });
    await expect(buildUserInfo(token)).rejects.toMatchObject({ error: "invalid_token" });
  });
});

describe("tokens end with their session", () => {
  it("a password change cuts off other sessions' access tokens at once", async () => {
    const { user, password } = await createTestUser({ email: "tokens@example.com" });
    const { client } = await createTestClient();
    const stolen = await createAuthedSession(String(user._id));
    const mine = await createAuthedSession(String(user._id));
    const { token } = await issueAccessToken({
      clientId: client.clientId, userId: user._id, sessionId: stolen.session._id, scope: "openid email",
    });
    expect(await resolveAccessToken(token)).toBeTruthy();

    await changeUserPassword(mine.token, { currentPassword: password, newPassword: "NewStrongPass2!" });
    expect(await resolveAccessToken(token)).toBeNull();
    await expect(buildUserInfo(token)).rejects.toMatchObject({ error: "invalid_token" });
  });
});

describe("one-time codes and refresh tokens under concurrency", () => {
  async function codeFor() {
    const { user } = await createTestUser({ email: `race-${generateSecureToken(4)}@example.com` });
    const { client, clientSecret } = await createTestClient();
    const { token: sessionToken } = await createAuthedSession(String(user._id));
    const verifier = generateSecureToken(32);
    const { code } = await createAuthorizationCode({
      sessionToken,
      clientId: client.clientId,
      redirectUri: client.redirectUris[0]!,
      scope: "openid profile email offline_access",
      codeChallenge: pkceChallenge(verifier),
      codeChallengeMethod: "S256",
    });
    const exchange = () => exchangeAuthorizationCode({
      code, redirectUri: client.redirectUris[0]!, clientId: client.clientId, clientSecret,
      codeVerifier: verifier, authorizationHeader: null,
    });
    return { client, clientSecret, exchange };
  }

  it("redeems an authorization code once, even when raced", async () => {
    const { exchange } = await codeFor();
    const results = await Promise.allSettled([exchange(), exchange(), exchange()]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
  });

  it("presenting a used code revokes the tokens it produced", async () => {
    const { exchange } = await codeFor();
    const first = await exchange();
    expect(await resolveAccessToken(first.access_token)).toBeTruthy();
    await expect(exchange()).rejects.toMatchObject({ error: "invalid_grant" });
    expect(await resolveAccessToken(first.access_token)).toBeNull();
    expect(await AccessToken.exists({ revokedAt: null })).toBeNull();
  });

  it("rotates a refresh token once when raced, and treats the rest as reuse", async () => {
    const { user } = await createTestUser({ email: "refresh-race@example.com" });
    const { client, clientSecret } = await createTestClient();
    const { session } = await createAuthedSession(String(user._id));
    const { token, familyId } = await issueRefreshToken({
      clientId: client.clientId, userId: user._id, sessionId: session._id, scope: "openid offline_access",
    });
    const refresh = () => exchangeRefreshToken({
      refreshToken: token, clientId: client.clientId, clientSecret, authorizationHeader: null,
    });
    const results = await Promise.allSettled([refresh(), refresh(), refresh()]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    // The losers looked like reuse, so the family (including the winner's new token) is revoked.
    expect(await RefreshToken.exists({ familyId, revokedAt: null })).toBeNull();
  });
});
