import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { GET as authorize } from "@/app/api/oauth/authorize/route";
import { POST as tokenRoute } from "@/app/api/oauth/token/route";
import { GET as userinfoGet, POST as userinfoPost } from "@/app/api/oidc/userinfo/route";
import { CONFORMANCE_CLIENT_IDS, CONFORMANCE_EMAIL, createConformanceSetup, removeConformanceSetup } from "@/lib/conformance/setup";
import { getEnv } from "@/lib/config/env";
import { createIdToken } from "@/lib/oidc/id-token";
import { performLogout } from "@/lib/oidc/logout";
import { verifyPassword } from "@/lib/security/password";
import { createSession } from "@/lib/sessions/session-service";
import { issueAccessToken } from "@/lib/tokens/token-service";
import { OAuthClient } from "@/models/OAuthClient";
import { User } from "@/models/User";
import { createTestClient, createTestUser } from "./helpers";

const jar = vi.hoisted(() => new Map<string, string>());
vi.mock("next/headers", () => ({ cookies: async () => ({ get: (key: string) => (jar.has(key) ? { value: jar.get(key) } : undefined) }) }));
beforeEach(() => jar.clear());

async function signedIn(email = "user@example.com") {
  const { user } = await createTestUser({ email });
  const { token, session } = await createSession({ userId: user._id, methods: ["password"] });
  jar.set(getEnv().SESSION_COOKIE_NAME, token);
  return { user: (await User.findById(user._id))!, session };
}

/** A confidential client without PKCE, as the conformance suite's are. */
async function suiteClient() {
  const created = await createTestClient({ requirePkce: false });
  return created;
}

async function run(clientId: string, redirectUri: string, extra: Record<string, string> = {}) {
  const url = new URL("http://localhost:3000/api/oauth/authorize");
  for (const [k, v] of Object.entries({ client_id: clientId, redirect_uri: redirectUri, response_type: "code", scope: "openid", ...extra })) url.searchParams.set(k, v);
  const response = await authorize(new NextRequest(url));
  const location = response.headers.get("location");
  return { response, location: location ? new URL(location) : null };
}

describe("authorization requests the suite sends", () => {
  it("requires state, and returns it unchanged", async () => {
    await signedIn();
    const { client } = await suiteClient();
    expect((await run(client.clientId, client.redirectUris[0]!)).response.status).toBe(400);
    const some = (await run(client.clientId, client.redirectUris[0]!, { state: "xyz" })).location!;
    expect(some.searchParams.get("code")).toBeTruthy();
    expect(some.searchParams.get("state")).toBe("xyz");
  });

  it("answers request objects with request_not_supported, at a known app's redirect URI only", async () => {
    const { client } = await suiteClient();
    const req = (await run(client.clientId, client.redirectUris[0]!, { request: "eyJhbGciOiJub25lIn0.e30.", state: "s" })).location!;
    expect(req.searchParams.get("error")).toBe("request_not_supported");
    expect(req.searchParams.get("state")).toBe("s");
    const uri = (await run(client.clientId, client.redirectUris[0]!, { request_uri: "https://example.com/r", state: "s" })).location!;
    expect(uri.searchParams.get("error")).toBe("request_uri_not_supported");
    // An address the app never registered gets no redirect.
    const stranger = await run(client.clientId, "https://evil.example.com/cb", { request: "x", state: "s" });
    expect(stranger.location).toBeNull();
    expect(stranger.response.status).toBeGreaterThanOrEqual(400);
  });

  it("honours id_token_hint: the named account answers, another gets login_required, a bad hint is ignored", async () => {
    const { user, session } = await signedIn();
    const { client } = await suiteClient();
    const mine = await createIdToken({ user, clientId: client.clientId, scope: "openid", authTime: new Date(), sessionId: session._id });
    expect((await run(client.clientId, client.redirectUris[0]!, { prompt: "none", id_token_hint: mine, state: "s" })).location!.searchParams.get("code")).toBeTruthy();

    const other = (await createTestUser({ email: "other@example.com" })).user;
    const theirs = await createIdToken({ user: (await User.findById(other._id))!, clientId: client.clientId, scope: "openid", authTime: new Date(), sessionId: session._id });
    expect((await run(client.clientId, client.redirectUris[0]!, { prompt: "none", id_token_hint: theirs, state: "s" })).location!.searchParams.get("error")).toBe("login_required");
    expect((await run(client.clientId, client.redirectUris[0]!, { prompt: "none", id_token_hint: "not-a-token", state: "s" })).location!.searchParams.get("code")).toBeTruthy();
  });
});

describe("UserInfo and token endpoint, as RFC 6750 and 6749 describe", () => {
  it("takes the access token from a POST form body, and says how to authenticate when it's missing or bad", async () => {
    const { user, session } = await signedIn();
    const { client } = await suiteClient();
    const access = await issueAccessToken({ clientId: client.clientId, userId: user._id, sessionId: session._id, scope: "openid email" });
    const body = await userinfoPost(new NextRequest("http://localhost:3000/api/oidc/userinfo", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: `access_token=${access.token}` }));
    expect(await body.json()).toMatchObject({ sub: String(user._id), email: user.email });

    const missing = await userinfoGet(new NextRequest("http://localhost:3000/api/oidc/userinfo"));
    expect(missing.status).toBe(401);
    expect(missing.headers.get("www-authenticate")).toMatch(/^Bearer error="invalid_token"/);
    const bad = await userinfoGet(new NextRequest("http://localhost:3000/api/oidc/userinfo", { headers: { authorization: "Bearer nope" } }));
    expect(bad.headers.get("www-authenticate")).toContain('error="invalid_token"');
    // Never from the query string.
    const query = await userinfoGet(new NextRequest(`http://localhost:3000/api/oidc/userinfo?access_token=${access.token}`));
    expect(query.status).toBe(401);
  });

  it("answers a failed client authentication with WWW-Authenticate: Basic", async () => {
    const { client } = await suiteClient();
    const response = await tokenRoute(new NextRequest("http://localhost:3000/api/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", authorization: `Basic ${Buffer.from(`${client.clientId}:wrong`).toString("base64")}` },
      body: "grant_type=authorization_code&code=x&redirect_uri=https%3A%2F%2Fexample.com",
    }));
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toContain("Basic");
  });
});

describe("RP-initiated logout", () => {
  it("finds the app from id_token_hint when client_id is left out, and refuses a mismatch", async () => {
    const { user, session } = await signedIn();
    const { client } = await suiteClient();
    const hint = await createIdToken({ user, clientId: client.clientId, scope: "openid", authTime: new Date(), sessionId: session._id });
    const result = await performLogout({ idTokenHint: hint, postLogoutRedirectUri: client.postLogoutRedirectUris[0]!, state: "bye" });
    expect(result.redirectTo).toBe(`${client.postLogoutRedirectUris[0]}?state=bye`);
    await expect(performLogout({ idTokenHint: hint, clientId: "someone-else", postLogoutRedirectUri: client.postLogoutRedirectUris[0]! })).rejects.toMatchObject({ error: "invalid_request" });
    await expect(performLogout({ postLogoutRedirectUri: client.postLogoutRedirectUris[0]! })).rejects.toMatchObject({ error: "invalid_request" });
  });
});

describe("conformance setup", () => {
  it("registers the suite's two clients and a test account, and removes them again", async () => {
    const setup = await createConformanceSetup({ issuer: "https://staging.noirly.test/", suiteUrl: "https://www.certification.openid.net", alias: "noirly" });
    expect(setup.suiteConfig).toMatchObject({ alias: "noirly", server: { discoveryUrl: "https://staging.noirly.test/.well-known/openid-configuration" } });
    for (const [clientId, conf] of [[CONFORMANCE_CLIENT_IDS[0], setup.suiteConfig.client], [CONFORMANCE_CLIENT_IDS[1], setup.suiteConfig.client2]] as const) {
      const stored = await OAuthClient.findOne({ clientId }).select("+clientSecretHash").lean();
      expect(stored).toMatchObject({
        redirectUris: ["https://www.certification.openid.net/test/a/noirly/callback"],
        postLogoutRedirectUris: ["https://www.certification.openid.net/test/a/noirly/post_logout_redirect"],
        backchannelLogoutUri: "https://www.certification.openid.net/test/a/noirly/backchannel_logout",
        requirePkce: false,
        requireConsent: false,
      });
      expect(await verifyPassword(stored!.clientSecretHash!, conf.client_secret)).toBe(true);
    }
    const account = await User.findOne({ email: CONFORMANCE_EMAIL }).select("+passwordHash").lean();
    expect(account?.emailVerified).toBe(true);
    expect(await verifyPassword(account!.passwordHash!, setup.account.password)).toBe(true);

    // Running again replaces the secrets.
    const again = await createConformanceSetup({ issuer: "https://staging.noirly.test", suiteUrl: "https://www.certification.openid.net", alias: "noirly" });
    expect(again.suiteConfig.client.client_secret).not.toBe(setup.suiteConfig.client.client_secret);
    expect(await removeConformanceSetup()).toEqual({ clients: 2, users: 1 });
    await expect(createConformanceSetup({ issuer: "https://x.test", suiteUrl: "https://s.test", alias: "Bad Alias" })).rejects.toThrow(/alias/);
  });
});
