import { describe, expect, it } from "vitest";
import { sameOriginPath, sanitizeReturnTo } from "@/lib/auth/return-to";
import { safeReturnTo } from "@/lib/auth/oauth-state";
import { loginWithGoogleProfile } from "@/lib/auth/google";
import { changeUserPassword, registerUser } from "@/lib/auth/auth-service";
import { createAuthorizationCode } from "@/lib/oauth/authorize";
import { exchangeAuthorizationCode, exchangeRefreshToken } from "@/lib/oauth/token";
import { buildUserInfo } from "@/lib/oidc/userinfo";
import { issueAccessToken, issueRefreshToken, resolveAccessToken } from "@/lib/tokens/token-service";
import { generateSecureToken } from "@/lib/security/crypto";
import { validateSession } from "@/lib/sessions/session-service";
import { AccessToken } from "@/models/AccessToken";
import { RefreshToken } from "@/models/RefreshToken";
import { LinkedAccount } from "@/models/LinkedAccount";
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
});

describe("a provider can't claim an account", () => {
  it("leaves an unverified registrant's account exactly as it was", async () => {
    const { user: squatter } = await createTestUser({ email: "victim@example.com", status: "pending_verification" });
    await expect(loginWithGoogleProfile({
      sub: "victim-google", email: "victim@example.com", emailVerified: true,
      firstName: "Real", lastName: "Owner", displayName: "Real Owner", avatarUrl: null,
    }, {})).rejects.toMatchObject({ code: "provider_sign_in_off" });
    expect((await User.findById(squatter._id).lean())!.emailVerified).toBe(false);
    expect(await LinkedAccount.exists({ providerAccountId: "victim-google" })).toBeNull();
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
