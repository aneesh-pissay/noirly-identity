import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { decodeJwt } from "jose";
import { GET as authorize } from "@/app/api/oauth/authorize/route";
import { getEnv } from "@/lib/config/env";
import { exchangeAuthorizationCode } from "@/lib/oauth/token";
import { parseClaimsRequest } from "@/lib/oidc/claims-request";
import { buildDiscoveryDocument } from "@/lib/oidc/discovery";
import { buildUserInfo } from "@/lib/oidc/userinfo";
import { generateSecureToken } from "@/lib/security/crypto";
import { createSession } from "@/lib/sessions/session-service";
import { createTestClient, createTestUser, pkceChallenge } from "./helpers";

const jar = vi.hoisted(() => new Map<string, string>());
vi.mock("next/headers", () => ({ cookies: async () => ({ get: (key: string) => (jar.has(key) ? { value: jar.get(key) } : undefined) }) }));
beforeEach(() => jar.clear());

async function signedIn() {
  const { user } = await createTestUser();
  const { token } = await createSession({ userId: user._id, methods: ["password"] });
  jar.set(getEnv().SESSION_COOKIE_NAME, token);
  return user;
}

async function run(client: { clientId: string; redirectUris: string[] }, extra: Record<string, string>) {
  const verifier = generateSecureToken(32);
  const url = new URL("http://localhost:3000/api/oauth/authorize");
  for (const [k, v] of Object.entries({ client_id: client.clientId, redirect_uri: client.redirectUris[0]!, response_type: "code", scope: "openid", state: "st", code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", ...extra })) url.searchParams.set(k, v);
  const location = new URL((await authorize(new NextRequest(url))).headers.get("location")!);
  return { location, verifier };
}

describe("claims follow scopes", () => {
  it("gives only what the granted scopes allow, in UserInfo and the ID token alike", async () => {
    const user = await signedIn();
    const { client, clientSecret } = await createTestClient();
    const { location, verifier } = await run(client, { scope: "openid email" });
    const tokens = await exchangeAuthorizationCode({ code: location.searchParams.get("code")!, redirectUri: client.redirectUris[0]!, codeVerifier: verifier, clientId: client.clientId, clientSecret, authorizationHeader: null });
    const id = decodeJwt(tokens.id_token);
    expect(id).toMatchObject({ sub: String(user._id), email: user.email, email_verified: true });
    expect(id.name).toBeUndefined();
    expect(id.locale).toBeUndefined();
    expect(await buildUserInfo(tokens.access_token)).toEqual({ sub: String(user._id), email: user.email, email_verified: true });
  });
});

describe("the claims request parameter", () => {
  it("parses what it understands and ignores claims it doesn't know", () => {
    expect(parseClaimsRequest(JSON.stringify({ userinfo: { email: null, made_up: null }, id_token: { name: { essential: true }, acr: { essential: true, values: ["urn:noirly:acr:mfa"] }, sub: { value: "abc" } } })))
      .toEqual({ scopes: ["email", "profile"], essentialAcr: ["urn:noirly:acr:mfa"], sub: "abc" });
    // A voluntary acr is only a hint.
    expect(parseClaimsRequest(JSON.stringify({ id_token: { acr: { values: ["urn:noirly:acr:mfa"] } } })).essentialAcr).toEqual([]);
    expect(parseClaimsRequest(undefined)).toEqual({ scopes: [], essentialAcr: [], sub: null });
    expect(() => parseClaimsRequest("{nope")).toThrow(/JSON/);
    expect(() => parseClaimsRequest(JSON.stringify({ userinfo: { email: "yes" } }))).toThrow(/claims/);
  });

  it("turns claims asked for into their scopes, which the grant and consent then cover", async () => {
    const user = await signedIn();
    const { client, clientSecret } = await createTestClient({ allowedScopes: ["openid", "profile", "email"] });
    const { location, verifier } = await run(client, { claims: JSON.stringify({ id_token: { email: { essential: true } }, userinfo: { roles: null } }) });
    const tokens = await exchangeAuthorizationCode({ code: location.searchParams.get("code")!, redirectUri: client.redirectUris[0]!, codeVerifier: verifier, clientId: client.clientId, clientSecret, authorizationHeader: null });
    // email is allowed for this app and came with it; roles isn't, so it didn't.
    expect(tokens.scope).toBe("openid email");
    expect(decodeJwt(tokens.id_token)).toMatchObject({ email: user.email });
    expect(decodeJwt(tokens.id_token).roles).toBeUndefined();

    // An app that asks for consent shows the added scope on the consent page.
    const asking = await createTestClient({ allowedScopes: ["openid", "profile", "email"], requireConsent: true });
    const consent = (await run(asking.client, { claims: JSON.stringify({ userinfo: { name: null } }) })).location;
    expect(consent.pathname).toBe("/consent");
    expect(consent.searchParams.get("scope")).toBe("openid profile");
  });

  it("only lets the named account answer when sub is asked for by value", async () => {
    const user = await signedIn();
    const { client } = await createTestClient();
    const mine = await run(client, { prompt: "none", claims: JSON.stringify({ id_token: { sub: { value: String(user._id) } } }) });
    expect(mine.location.searchParams.get("code")).toBeTruthy();
    const someoneElse = await run(client, { prompt: "none", claims: JSON.stringify({ id_token: { sub: { value: "000000000000000000000000" } } }) });
    expect(someoneElse.location.searchParams.get("error")).toBe("login_required");
    const interactive = await run(client, { claims: JSON.stringify({ id_token: { sub: { value: "000000000000000000000000" } } }) });
    expect(interactive.location.pathname).toBe("/login");
  });

  it("treats an essential acr as a step-up, and sends malformed claims back to the app", async () => {
    await signedIn();
    const { client } = await createTestClient();
    const stepUp = await run(client, { prompt: "none", claims: JSON.stringify({ id_token: { acr: { essential: true, values: ["urn:noirly:acr:mfa"] } } }) });
    expect(stepUp.location.searchParams.get("error")).toBe("interaction_required");
    const broken = await run(client, { claims: "{nope" });
    expect(broken.location.origin + broken.location.pathname).toBe(client.redirectUris[0]);
    expect(broken.location.searchParams.get("error")).toBe("invalid_request");
    expect(buildDiscoveryDocument()).toMatchObject({ claims_parameter_supported: true, request_parameter_supported: false });
  });
});
