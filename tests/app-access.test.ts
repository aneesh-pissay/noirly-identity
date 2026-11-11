import { describe, expect, it } from "vitest";
import { describeScopes } from "@/lib/account/app-scopes";
import { listAppAccess } from "@/lib/account/app-access";
import { deleteUserAccount } from "@/lib/account/delete-account";
import { createAuthorizationCode } from "@/lib/oauth/authorize";
import { exchangeAuthorizationCode, exchangeRefreshToken } from "@/lib/oauth/token";
import { buildUserInfo } from "@/lib/oidc/userinfo";
import { generateSecureToken } from "@/lib/security/crypto";
import { revokeAllUserSessions } from "@/lib/sessions/session-service";
import { AppAccess } from "@/models/AppAccess";
import { RefreshToken } from "@/models/RefreshToken";
import { createAuthedSession, createTestClient, createTestUser, pkceChallenge } from "./helpers";

async function signInTo(userId: string, client: { clientId: string; redirectUris: string[] }, clientSecret: string, scope: string) {
  const { token: sessionToken } = await createAuthedSession(userId);
  const verifier = generateSecureToken(32);
  const { code } = await createAuthorizationCode({ sessionToken, clientId: client.clientId, redirectUri: client.redirectUris[0]!, scope, codeChallenge: pkceChallenge(verifier), codeChallengeMethod: "S256" });
  return exchangeAuthorizationCode({ code, redirectUri: client.redirectUris[0]!, clientId: client.clientId, clientSecret, codeVerifier: verifier, authorizationHeader: null });
}

describe("what apps can see", () => {
  it("puts scopes in words, in a steady order", () => {
    expect(describeScopes(["email", "openid", "custom", "email"])).toEqual(["That it's you, by your Noirly account ID", "Your primary email address and whether it's confirmed", "custom"]);
  });
});

describe("apps using an account", () => {
  it("records each app that gets a token, what it can see, and whether it's signed in now", async () => {
    const { user } = await createTestUser();
    const id = String(user._id);
    const first = await createTestClient();
    const second = await createTestClient({ clientType: "public" });
    await signInTo(id, first.client, first.clientSecret, "openid email");
    const tokens = await signInTo(id, first.client, first.clientSecret, "openid profile offline_access");
    await signInTo(id, second.client, "", "openid");

    const apps = await listAppAccess(id);
    expect(apps.map((a) => a.clientId)).toEqual([second.client.clientId, first.client.clientId]);
    expect(apps[1]).toMatchObject({ name: "Test App (Development)", kind: "web", signedIn: true, scopes: expect.arrayContaining(["openid", "email", "profile", "offline_access"]) });
    expect(apps[1]!.canSee).toHaveLength(4);
    expect(apps[0]).toMatchObject({ kind: "mobile" });

    // A refresh counts as use.
    const before = (await AppAccess.findOne({ clientId: first.client.clientId }).lean())!.lastUsedAt;
    await new Promise((resolve) => setTimeout(resolve, 5));
    await exchangeRefreshToken({ refreshToken: tokens.refresh_token!, clientId: first.client.clientId, clientSecret: first.clientSecret, authorizationHeader: null });
    expect((await AppAccess.findOne({ clientId: first.client.clientId }).lean())!.lastUsedAt.getTime()).toBeGreaterThan(before.getTime());

    // Signed out everywhere: the apps stay listed, no longer signed in.
    await revokeAllUserSessions(user._id);
    expect((await listAppAccess(id)).every((a) => !a.signedIn)).toBe(true);
  });

  it("moves 'last used' on UserInfo reads, but not on every one", async () => {
    const { user } = await createTestUser();
    const { client, clientSecret } = await createTestClient();
    const tokens = await signInTo(String(user._id), client, clientSecret, "openid profile");
    const earlier = new Date(Date.now() - 60 * 60_000);
    await AppAccess.updateOne({ clientId: client.clientId }, { $set: { lastUsedAt: earlier } });
    await buildUserInfo(tokens.access_token);
    const moved = (await AppAccess.findOne({ clientId: client.clientId }).lean())!.lastUsedAt;
    expect(moved.getTime()).toBeGreaterThan(earlier.getTime());
    await buildUserInfo(tokens.access_token);
    expect((await AppAccess.findOne({ clientId: client.clientId }).lean())!.lastUsedAt.getTime()).toBe(moved.getTime());
  });

  it("fills in from tokens issued before it was recorded, and goes with the account", async () => {
    const { user } = await createTestUser();
    const { session } = await createAuthedSession(String(user._id));
    await RefreshToken.create({ tokenHash: "h1", familyId: "f1", clientId: "older-app", userId: user._id, sessionId: session._id, scope: "openid email", expiresAt: new Date(Date.now() + 86_400_000) });
    const apps = await listAppAccess(String(user._id));
    expect(apps).toEqual([expect.objectContaining({ clientId: "older-app", name: "older-app", signedIn: true })]);
    await deleteUserAccount(user._id);
    expect(await AppAccess.countDocuments()).toBe(0);
  });
});
