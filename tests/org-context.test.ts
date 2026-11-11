import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { decodeJwt } from "jose";
import { GET as authorize } from "@/app/api/oauth/authorize/route";
import { getEnv } from "@/lib/config/env";
import { introspectToken } from "@/lib/oauth/introspect";
import { exchangeAuthorizationCode, exchangeRefreshToken } from "@/lib/oauth/token";
import { buildDiscoveryDocument } from "@/lib/oidc/discovery";
import { buildUserInfo } from "@/lib/oidc/userinfo";
import { generateSecureToken } from "@/lib/security/crypto";
import { createSession } from "@/lib/sessions/session-service";
import { createSpace, removeMember } from "@/lib/spaces/space-service";
import { OAuthClient } from "@/models/OAuthClient";
import { createTestClient, createTestUser, pkceChallenge } from "./helpers";

const jar = vi.hoisted(() => new Map<string, string>());
vi.mock("next/headers", () => ({ cookies: async () => ({ get: (key: string) => (jar.has(key) ? { value: jar.get(key) } : undefined) }) }));
beforeEach(() => jar.clear());

async function setup() {
  const { user: owner } = await createTestUser({ email: "owner@example.com" });
  const { user: alice } = await createTestUser({ email: "alice@example.com" });
  const id = String(alice._id);
  const studio = await createSpace({ ownerId: String(owner._id), name: "Studio", members: [{ userId: id, role: "admin" }] });
  const lab = await createSpace({ ownerId: String(owner._id), name: "Lab", members: [{ userId: id, role: "member" }] });
  const elsewhere = await createSpace({ ownerId: String(owner._id), name: "Elsewhere" });
  const { client, clientSecret } = await createTestClient({ allowedScopes: ["openid", "profile", "email", "offline_access", "organizations"] });
  const { token } = await createSession({ userId: id, methods: ["password"] });
  jar.set(getEnv().SESSION_COOKIE_NAME, token);
  return { alice, id, studio, lab, elsewhere, client, clientSecret };
}

async function codeFor(client: { clientId: string; redirectUris: string[] }, extra: Record<string, string>) {
  const verifier = generateSecureToken(32);
  const url = new URL("http://localhost:3000/api/oauth/authorize");
  for (const [k, v] of Object.entries({ client_id: client.clientId, redirect_uri: client.redirectUris[0]!, response_type: "code", scope: "openid offline_access", state: "st", code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", ...extra })) url.searchParams.set(k, v);
  const location = new URL((await authorize(new NextRequest(url))).headers.get("location")!);
  return { location, verifier };
}

describe("organization context", () => {
  it("scopes tokens to the chosen organization: ID token, UserInfo, introspection, and refresh", async () => {
    const { studio, client, clientSecret } = await setup();
    const { location, verifier } = await codeFor(client, { organization: studio.slug });
    const tokens = await exchangeAuthorizationCode({ code: location.searchParams.get("code")!, redirectUri: client.redirectUris[0]!, codeVerifier: verifier, clientId: client.clientId, clientSecret, authorizationHeader: null });
    expect(decodeJwt(tokens.id_token)).toMatchObject({ org_id: studio.id, org_slug: studio.slug, org_role: "admin" });
    expect(await buildUserInfo(tokens.access_token)).toMatchObject({ org_id: studio.id, org_role: "admin" });
    expect(await introspectToken(tokens.access_token, "api")).toMatchObject({ active: true, org_id: studio.id });

    const refreshed = await exchangeRefreshToken({ refreshToken: tokens.refresh_token!, clientId: client.clientId, clientSecret, authorizationHeader: null });
    expect(decodeJwt(refreshed.id_token)).toMatchObject({ org_id: studio.id });
  });

  it("switches by asking again, silently, for another organization", async () => {
    const { lab, client, clientSecret } = await setup();
    const { location, verifier } = await codeFor(client, { organization: lab.id, prompt: "none" });
    const tokens = await exchangeAuthorizationCode({ code: location.searchParams.get("code")!, redirectUri: client.redirectUris[0]!, codeVerifier: verifier, clientId: client.clientId, clientSecret, authorizationHeader: null });
    expect(decodeJwt(tokens.id_token)).toMatchObject({ org_id: lab.id, org_role: "member" });
  });

  it("never lets someone into an organization they aren't in; offers the picker instead", async () => {
    const { elsewhere, client } = await setup();
    expect((await codeFor(client, { organization: elsewhere.id, prompt: "none" })).location.searchParams.get("error")).toBe("access_denied");
    const picker = (await codeFor(client, { organization: elsewhere.id })).location;
    expect(picker.pathname).toBe("/choose-organization");
    expect(new URL(picker.searchParams.get("return_to")!).pathname).toBe("/api/oauth/authorize");
    expect((await codeFor(client, { organization: "select", prompt: "none" })).location.searchParams.get("error")).toBe("interaction_required");
    expect((await codeFor(client, { organization: "select" })).location.pathname).toBe("/choose-organization");
  });

  it("ends a scoped grant once the person leaves the organization", async () => {
    const { id, studio, client, clientSecret } = await setup();
    const { location, verifier } = await codeFor(client, { organization: studio.id });
    const tokens = await exchangeAuthorizationCode({ code: location.searchParams.get("code")!, redirectUri: client.redirectUris[0]!, codeVerifier: verifier, clientId: client.clientId, clientSecret, authorizationHeader: null });
    await removeMember(id, studio.id, id);
    await expect(exchangeRefreshToken({ refreshToken: tokens.refresh_token!, clientId: client.clientId, clientSecret, authorizationHeader: null })).rejects.toMatchObject({ error: "invalid_grant" });
    await expect(buildUserInfo(tokens.access_token)).rejects.toMatchObject({ error: "invalid_token" });
    expect(await introspectToken(tokens.access_token, "api")).toEqual({ active: false });
  });

  it("lists every organization under the organizations scope, without scoping the tokens", async () => {
    const { client, clientSecret } = await setup();
    await OAuthClient.updateOne({ clientId: client.clientId }, { $set: { allowedScopes: ["openid", "organizations"] } });
    const { location, verifier } = await codeFor(client, { scope: "openid organizations" });
    const tokens = await exchangeAuthorizationCode({ code: location.searchParams.get("code")!, redirectUri: client.redirectUris[0]!, codeVerifier: verifier, clientId: client.clientId, clientSecret, authorizationHeader: null });
    const id = decodeJwt(tokens.id_token);
    expect((id.organizations as Array<{ name: string; role: string }>).map((o) => `${o.name}:${o.role}`)).toEqual(["Lab:member", "Studio:admin"]);
    expect(id.org_id).toBeUndefined();
    expect(buildDiscoveryDocument().claims_supported).toEqual(expect.arrayContaining(["org_id", "org_role", "organizations"]));
  });
});
