import { existsSync } from "node:fs";
import { join } from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { decodeJwt } from "jose";
import { GET as openidConfiguration } from "@/app/.well-known/openid-configuration/route";
import { GET as authorize } from "@/app/api/oauth/authorize/route";
import { POST as revoke } from "@/app/api/oauth/revoke/route";
import { getEnv } from "@/lib/config/env";
import { createIdToken } from "@/lib/oidc/id-token";
import { orgClaims } from "@/lib/oauth/org-context";
import { createSpace } from "@/lib/spaces/space-service";
import { buildDiscoveryDocument } from "@/lib/oidc/discovery";
import { buildUserInfo } from "@/lib/oidc/userinfo";
import { generateSecureToken } from "@/lib/security/crypto";
import { createSession } from "@/lib/sessions/session-service";
import { issueAccessToken, resolveAccessToken } from "@/lib/tokens/token-service";
import { authorizeQuerySchema } from "@/lib/validation/schemas";
import { User } from "@/models/User";
import { SUPPORTED_SCOPES } from "@/types";
import { createTestClient, createTestUser, pkceChallenge } from "./helpers";

const jar = vi.hoisted(() => new Map<string, string>());
vi.mock("next/headers", () => ({ cookies: async () => ({ get: (key: string) => (jar.has(key) ? { value: jar.get(key) } : undefined) }) }));
beforeEach(() => jar.clear());

const doc = () => buildDiscoveryDocument();

describe("discovery tells the truth", () => {
  it("is served at the well-known address, cacheable", async () => {
    const response = await openidConfiguration();
    expect(await response.json()).toEqual(doc());
    expect(response.headers.get("cache-control")).toContain("max-age");
  });

  it("names only endpoints that exist, under the issuer", () => {
    const endpoints = Object.entries(doc()).filter(([key]) => key.endsWith("_endpoint") || key === "jwks_uri");
    expect(endpoints.length).toBeGreaterThanOrEqual(8);
    for (const [key, url] of endpoints) {
      const { pathname, origin } = new URL(url as string);
      expect(origin, key).toBe("http://localhost:3000");
      expect(existsSync(join(process.cwd(), "app", pathname, "route.ts")), `${key} → app${pathname}/route.ts`).toBe(true);
    }
  });

  it("advertises exactly the values the authorization endpoint accepts", () => {
    const shape = authorizeQuerySchema.shape;
    for (const prompt of doc().prompt_values_supported) expect(shape.prompt.safeParse(prompt).success).toBe(true);
    expect(shape.prompt.safeParse("create").success).toBe(false);
    for (const display of doc().display_values_supported) expect(shape.display.safeParse(display).success).toBe(true);
    for (const method of doc().code_challenge_methods_supported) expect(shape.code_challenge_method.safeParse(method).success).toBe(true);
    expect(shape.code_challenge_method.safeParse("plain").success).toBe(false);
    expect(doc().scopes_supported).toEqual([...SUPPORTED_SCOPES]);
  });

  it("lists every claim Identity can give, and gives every claim it lists", async () => {
    const { user } = await createTestUser();
    await User.updateOne({ _id: user._id }, { $set: { avatarUrl: "https://example.com/me.png", locale: "en-IN", zoneinfo: "Asia/Kolkata", roles: ["user"] } });
    const full = (await User.findById(user._id))!;
    const { session } = await createSession({ userId: user._id, methods: ["password", "totp"] });
    const scope = SUPPORTED_SCOPES.join(" ");
    // Signed in to one of their organizations, so the org_* claims come too.
    const space = await createSpace({ ownerId: String(user._id), name: "Claims Co" });
    const organization = await orgClaims(space.id, user._id);
    const idToken = decodeJwt(await createIdToken({ user: full, clientId: "noirly-crm", scope, nonce: "n", authTime: new Date(), methods: ["password", "totp"], sessionId: session._id, organization }));
    const { client } = await createTestClient();
    const access = await issueAccessToken({ clientId: client.clientId, userId: user._id, sessionId: session._id, scope });
    const given = new Set([...Object.keys(idToken), ...Object.keys(await buildUserInfo(access.token))]);
    for (const claim of doc().claims_supported) expect(given.has(claim), claim).toBe(true);
    for (const claim of given) expect(doc().claims_supported, claim).toContain(claim);
  });

  it("puts iss on authorization responses, codes and errors alike (RFC 9207)", async () => {
    const { user } = await createTestUser();
    const { token } = await createSession({ userId: user._id, methods: ["password"] });
    jar.set(getEnv().SESSION_COOKIE_NAME, token);
    const { client } = await createTestClient();
    const run = async (extra: Record<string, string>) => {
      const url = new URL("http://localhost:3000/api/oauth/authorize");
      for (const [k, v] of Object.entries({ client_id: client.clientId, redirect_uri: client.redirectUris[0]!, response_type: "code", scope: "openid", state: "st", code_challenge: pkceChallenge(generateSecureToken(32)), code_challenge_method: "S256", ...extra })) url.searchParams.set(k, v);
      return new URL((await authorize(new NextRequest(url))).headers.get("location")!);
    };
    const ok = await run({});
    expect(ok.searchParams.get("code")).toBeTruthy();
    expect(ok.searchParams.get("iss")).toBe(doc().issuer);
    const bad = await run({ scope: "openid nonsense" });
    expect(bad.searchParams.get("error")).toBe("invalid_scope");
    expect(bad.searchParams.get("iss")).toBe(doc().issuer);
    expect(doc().authorization_response_iss_parameter_supported).toBe(true);
  });

  it("revokes with every advertised client authentication method", async () => {
    const { user } = await createTestUser();
    const { session } = await createSession({ userId: user._id });
    const { client, clientSecret } = await createTestClient();
    const mint = () => issueAccessToken({ clientId: client.clientId, userId: user._id, sessionId: session._id, scope: "openid" });
    const call = (body: Record<string, string>, authorization?: string) => revoke(new NextRequest("http://localhost:3000/api/oauth/revoke", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", ...(authorization ? { authorization } : {}) }, body: new URLSearchParams(body).toString() }));
    expect(doc().revocation_endpoint_auth_methods_supported).toEqual(["client_secret_basic", "client_secret_post", "none"]);

    const basic = await mint();
    expect((await call({ token: basic.token }, `Basic ${Buffer.from(`${client.clientId}:${clientSecret}`).toString("base64")}`)).status).toBe(200);
    expect(await resolveAccessToken(basic.token)).toBeNull();

    const post = await mint();
    expect((await call({ token: post.token, client_id: client.clientId, client_secret: clientSecret })).status).toBe(200);
    expect(await resolveAccessToken(post.token)).toBeNull();

    // A wrong secret is refused, and the token lives on.
    const kept = await mint();
    expect((await call({ token: kept.token }, `Basic ${Buffer.from(`${client.clientId}:wrong`).toString("base64")}`)).status).toBe(401);
    expect(await resolveAccessToken(kept.token)).not.toBeNull();
  });
});
