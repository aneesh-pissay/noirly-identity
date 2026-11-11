import { describe, expect, it } from "vitest";
import { NextRequest } from "next/server";
import { createLocalJWKSet, jwtVerify } from "jose";
import { POST as tokenRoute } from "@/app/api/oauth/token/route";
import { POST as revoke } from "@/app/api/oauth/revoke/route";
import { introspectToken } from "@/lib/oauth/introspect";
import { saveApiResource } from "@/lib/oauth/resources";
import { buildDiscoveryDocument } from "@/lib/oidc/discovery";
import { getJwks } from "@/lib/oidc/keys";
import { resolveAccessToken } from "@/lib/tokens/token-service";
import { OAuthClient } from "@/models/OAuthClient";
import { verifyAccessToken } from "../docs/examples/verify-tokens";
import { createTestClient } from "./helpers";

const API = "https://api.ledger.noirly.test";

async function setup() {
  const worker = await createTestClient();
  const other = await createTestClient();
  await saveApiResource({
    identifier: API,
    name: "Ledger API",
    scopes: [{ name: "ledger.read" }, { name: "ledger.write" }, { name: "ledger.admin" }],
    accessTokenTtlSeconds: 300,
    machineGrants: [{ clientId: worker.client.clientId, scopes: ["ledger.read", "ledger.write"] }],
  });
  return { worker, other };
}

const basic = (id: string, secret: string) => `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`;

function token(body: Record<string, string>, authorization?: string) {
  return tokenRoute(new NextRequest("http://localhost:3000/api/oauth/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", ...(authorization ? { authorization } : {}) },
    body: new URLSearchParams(body).toString(),
  }));
}

describe("client credentials (machine-to-machine)", () => {
  it("gives a granted app a JWT for one API, as itself, with its granted scopes", async () => {
    const { worker } = await setup();
    const auth = basic(worker.client.clientId, worker.clientSecret);
    const response = await token({ grant_type: "client_credentials", resource: API }, auth);
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toMatchObject({ token_type: "Bearer", expires_in: 300, scope: "ledger.read ledger.write" });
    expect(body.refresh_token).toBeUndefined();
    expect(body.id_token).toBeUndefined();

    const { payload, protectedHeader } = await jwtVerify(body.access_token, createLocalJWKSet(await getJwks()), { issuer: "http://localhost:3000", audience: API });
    expect(protectedHeader.typ).toBe("at+jwt");
    expect(payload).toMatchObject({ sub: worker.client.clientId, client_id: worker.client.clientId, scope: "ledger.read ledger.write" });
    expect(payload.sid).toBeUndefined();
    // The reference API check takes it as it is.
    await expect(verifyAccessToken(body.access_token, { issuer: "http://localhost:3000", jwks: createLocalJWKSet(await getJwks()), audience: API }, ["ledger.write"])).resolves.toBeTruthy();

    // Narrowing works; form credentials work too.
    const narrow = await (await token({ grant_type: "client_credentials", resource: API, scope: "ledger.read", client_id: worker.client.clientId, client_secret: worker.clientSecret })).json();
    expect(narrow.scope).toBe("ledger.read");
  });

  it("refuses scopes outside the grant, APIs without one, a missing resource, and apps without a grant", async () => {
    const { worker, other } = await setup();
    const auth = basic(worker.client.clientId, worker.clientSecret);
    expect(await (await token({ grant_type: "client_credentials", resource: API, scope: "ledger.admin" }, auth)).json()).toMatchObject({ error: "invalid_scope" });
    expect(await (await token({ grant_type: "client_credentials" }, auth)).json()).toMatchObject({ error: "invalid_target" });
    expect(await (await token({ grant_type: "client_credentials", resource: "https://api.other.noirly.test" }, auth)).json()).toMatchObject({ error: "invalid_target" });
    expect(await (await token({ grant_type: "client_credentials", resource: API }, basic(other.client.clientId, other.clientSecret))).json()).toMatchObject({ error: "invalid_target" });
    expect((await token({ grant_type: "client_credentials", resource: API }, basic(worker.client.clientId, "wrong"))).status).toBe(401);
    // Acting for people (allowedClientIds) isn't the same as acting alone.
    await saveApiResource({ identifier: API, name: "Ledger API", allowedClientIds: [other.client.clientId] });
    expect(await (await token({ grant_type: "client_credentials", resource: API }, basic(other.client.clientId, other.clientSecret))).json()).toMatchObject({ error: "invalid_target" });
  });

  it("never lets a public app act as itself", async () => {
    const mobile = await createTestClient({ clientType: "public" });
    await saveApiResource({ identifier: API, name: "Ledger API", scopes: [{ name: "ledger.read" }], machineGrants: [{ clientId: mobile.client.clientId, scopes: ["ledger.read"] }] });
    expect(await (await token({ grant_type: "client_credentials", resource: API, client_id: mobile.client.clientId })).json()).toMatchObject({ error: "unauthorized_client" });
  });

  it("is answered by introspection until the token, the app or the grant goes, and can be revoked", async () => {
    const { worker } = await setup();
    const auth = basic(worker.client.clientId, worker.clientSecret);
    const issue = async () => (await (await token({ grant_type: "client_credentials", resource: API }, auth)).json()).access_token as string;

    const first = await issue();
    expect(await introspectToken(first, "any-api")).toMatchObject({ active: true, sub: worker.client.clientId, client_id: worker.client.clientId, aud: API, scope: "ledger.read ledger.write" });
    // It speaks for no one at Identity's own endpoints.
    expect(await resolveAccessToken(first)).toBeNull();

    // Taking the grant away ends it.
    await saveApiResource({ identifier: API, name: "Ledger API", machineGrants: [] });
    expect(await introspectToken(first, "any-api")).toEqual({ active: false });
    await saveApiResource({ identifier: API, name: "Ledger API", machineGrants: [{ clientId: worker.client.clientId, scopes: ["ledger.read"] }] });

    // So does disabling the app.
    const second = await issue();
    await OAuthClient.updateOne({ clientId: worker.client.clientId }, { $set: { status: "disabled" } });
    expect(await introspectToken(second, "any-api")).toEqual({ active: false });
    await OAuthClient.updateOne({ clientId: worker.client.clientId }, { $set: { status: "active" } });

    // And the app can revoke its own token.
    const third = await issue();
    await revoke(new NextRequest("http://localhost:3000/api/oauth/revoke", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", authorization: auth }, body: new URLSearchParams({ token: third }).toString() }));
    expect(await introspectToken(third, "any-api")).toEqual({ active: false });
  });

  it("validates grants an admin sets, and is in discovery", async () => {
    const { worker } = await setup();
    await expect(saveApiResource({ identifier: API, name: "Ledger API", machineGrants: [{ clientId: worker.client.clientId, scopes: ["not.a.scope"] }] })).rejects.toMatchObject({ status: 400 });
    await expect(saveApiResource({ identifier: API, name: "Ledger API", machineGrants: [{ clientId: "a", scopes: [] }, { clientId: "a", scopes: [] }] })).rejects.toMatchObject({ status: 400 });
    expect(buildDiscoveryDocument().grant_types_supported).toContain("client_credentials");
  });
});
