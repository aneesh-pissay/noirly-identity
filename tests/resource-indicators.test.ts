import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from "jose";
import { GET as authorize } from "@/app/api/oauth/authorize/route";
import { POST as tokenRoute } from "@/app/api/oauth/token/route";
import { getEnv } from "@/lib/config/env";
import { introspectToken } from "@/lib/oauth/introspect";
import { saveApiResource } from "@/lib/oauth/resources";
import { getJwks } from "@/lib/oidc/keys";
import { sessionSid } from "@/lib/oidc/sid";
import { generateSecureToken } from "@/lib/security/crypto";
import { createSession, revokeSession } from "@/lib/sessions/session-service";
import { resolveAccessToken } from "@/lib/tokens/token-service";
import { AuthorizationCode } from "@/models/AuthorizationCode";
import { createTestClient, createTestUser, pkceChallenge } from "./helpers";

const jar = vi.hoisted(() => new Map<string, string>());
vi.mock("next/headers", () => ({ cookies: async () => ({ get: (key: string) => (jar.has(key) ? { value: jar.get(key) } : undefined) }) }));
beforeEach(() => jar.clear());

const CRM_API = "https://api.crm.noirly.test";
const DOCS_API = "https://api.docs.noirly.test";

async function setup() {
  const { user } = await createTestUser();
  const { client, clientSecret } = await createTestClient({ allowedScopes: ["openid", "profile", "email", "offline_access"] });
  await saveApiResource({ identifier: CRM_API, name: "CRM API", scopes: [{ name: "crm.read" }, { name: "crm.write" }], accessTokenTtlSeconds: 600, allowedClientIds: [client.clientId] });
  await saveApiResource({ identifier: DOCS_API, name: "Docs API", scopes: [{ name: "docs.read" }], allowedClientIds: [client.clientId] });
  const { token, session } = await createSession({ userId: user._id, methods: ["password"] });
  jar.set(getEnv().SESSION_COOKIE_NAME, token);
  return { user, client, clientSecret, session };
}

/** Runs authorize and returns the code (or the error redirect). */
async function codeFor(clientId: string, redirectUri: string, scope: string, resources: string[]) {
  const verifier = generateSecureToken(32);
  const url = new URL("http://localhost:3000/api/oauth/authorize");
  for (const [k, v] of Object.entries({ client_id: clientId, redirect_uri: redirectUri, response_type: "code", scope, state: "st", code_challenge: pkceChallenge(verifier), code_challenge_method: "S256" })) url.searchParams.set(k, v);
  for (const r of resources) url.searchParams.append("resource", r);
  const location = new URL((await authorize(new NextRequest(url))).headers.get("location")!);
  return { code: location.searchParams.get("code"), error: location.searchParams.get("error"), verifier };
}

function token(body: Record<string, string | string[]>, auth: { id: string; secret: string }) {
  const form = new URLSearchParams();
  for (const [k, v] of Object.entries(body)) for (const value of [v].flat()) form.append(k, value);
  return tokenRoute(new NextRequest("http://localhost:3000/api/oauth/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", authorization: `Basic ${Buffer.from(`${auth.id}:${auth.secret}`).toString("base64")}` },
    body: form.toString(),
  }));
}

describe("resource indicators (RFC 8707) and JWT access tokens (RFC 9068)", () => {
  it("gives an API a JWT it can verify offline, carrying only its own scopes", async () => {
    const { user, client, clientSecret, session } = await setup();
    const auth = { id: client.clientId, secret: clientSecret };
    const { code, verifier } = await codeFor(client.clientId, client.redirectUris[0]!, "openid profile offline_access crm.read docs.read", [CRM_API, DOCS_API]);
    expect(code).toBeTruthy();
    expect((await AuthorizationCode.findOne({}).lean())?.resources).toEqual([CRM_API, DOCS_API]);

    const response = await token({ grant_type: "authorization_code", code: code!, redirect_uri: client.redirectUris[0]!, code_verifier: verifier, resource: CRM_API }, auth);
    const body = await response.json();
    expect(response.status).toBe(200);
    expect(body).toMatchObject({ token_type: "Bearer", scope: "crm.read", expires_in: 600 });
    expect(body.id_token).toBeTruthy();

    expect(decodeProtectedHeader(body.access_token).typ).toBe("at+jwt");
    const { payload } = await jwtVerify(body.access_token, createLocalJWKSet(await getJwks()), { issuer: "http://localhost:3000", audience: CRM_API, typ: "at+jwt" });
    expect(payload).toMatchObject({ sub: String(user._id), client_id: client.clientId, scope: "crm.read", sid: sessionSid(session._id), acr: "urn:noirly:acr:1fa" });
    expect(payload.jti).toBeTruthy();
    expect((payload.exp as number) - (payload.iat as number)).toBe(600);

    // Not good at Identity's own endpoints; introspection names its audience.
    expect(await resolveAccessToken(body.access_token)).toBeNull();
    expect(await introspectToken(body.access_token, "any-api")).toMatchObject({ active: true, aud: CRM_API, scope: "crm.read" });

    // A refresh can get a token for the other API in the grant.
    const docs = await (await token({ grant_type: "refresh_token", refresh_token: body.refresh_token, resource: DOCS_API }, auth)).json();
    expect(docs.scope).toBe("docs.read");
    expect((await jwtVerify(docs.access_token, createLocalJWKSet(await getJwks()), { audience: DOCS_API })).payload.scope).toBe("docs.read");

    // Without a resource: the usual opaque token, with only the OpenID Connect scopes.
    const plain = await (await token({ grant_type: "refresh_token", refresh_token: docs.refresh_token }, auth)).json();
    expect(plain.scope).toBe("openid profile offline_access");
    expect(await resolveAccessToken(plain.access_token)).not.toBeNull();

    // Once the session ends, introspection says so (the JWT itself runs out within minutes).
    await revokeSession(session._id);
    expect(await introspectToken(body.access_token, "any-api")).toEqual({ active: false });
  });

  it("refuses resources that aren't registered, aren't for this app, or weren't granted, without spending the code", async () => {
    const { client, clientSecret } = await setup();
    const auth = { id: client.clientId, secret: clientSecret };
    const other = await createTestClient();
    await saveApiResource({ identifier: "https://api.private.noirly.test", name: "Private", allowedClientIds: [other.client.clientId] });

    expect((await codeFor(client.clientId, client.redirectUris[0]!, "openid", ["https://api.unknown.noirly.test"])).error).toBe("invalid_target");
    expect((await codeFor(client.clientId, client.redirectUris[0]!, "openid", ["https://api.private.noirly.test"])).error).toBe("invalid_target");
    // An API scope without its API is just an unknown scope.
    expect((await codeFor(client.clientId, client.redirectUris[0]!, "openid crm.read", [])).error).toBe("invalid_scope");

    const { code, verifier } = await codeFor(client.clientId, client.redirectUris[0]!, "openid crm.read", [CRM_API]);
    const exchange = (resource?: string | string[]) => token({ grant_type: "authorization_code", code: code!, redirect_uri: client.redirectUris[0]!, code_verifier: verifier, ...(resource ? { resource } : {}) }, auth);
    expect((await (await exchange(DOCS_API)).json()).error).toBe("invalid_target");
    expect((await (await exchange([CRM_API, DOCS_API])).json()).error).toBe("invalid_target");
    // The code survived those, and still works.
    expect((await exchange(CRM_API)).status).toBe(200);
  });

  it("validates what an admin registers", async () => {
    await expect(saveApiResource({ identifier: "not a uri", name: "x" })).rejects.toMatchObject({ status: 400 });
    await expect(saveApiResource({ identifier: "https://api.x.test#frag", name: "x" })).rejects.toMatchObject({ status: 400 });
    await expect(saveApiResource({ identifier: "https://api.x.test", name: "x", scopes: [{ name: "openid" }] })).rejects.toMatchObject({ status: 400 });
    await expect(saveApiResource({ identifier: "https://api.x.test", name: "x", accessTokenTtlSeconds: 86_400 })).rejects.toMatchObject({ status: 400 });
    const saved = await saveApiResource({ identifier: "https://api.x.test", name: "X", scopes: [{ name: "x.read", description: "Read X" }] });
    expect(saved).toMatchObject({ identifier: "https://api.x.test", accessTokenTtlSeconds: 900, status: "active" });
  });
});
