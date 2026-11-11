import { generateKeyPairSync } from "node:crypto";
import { createLocalJWKSet, importPKCS8, SignJWT, UnsecuredJWT, decodeJwt } from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import { getEnv } from "@/lib/config/env";
import { signLogoutToken } from "@/lib/oidc/backchannel-logout";
import { createIdToken } from "@/lib/oidc/id-token";
import { getJwks, rotateSigningKeys } from "@/lib/oidc/keys";
import { createSession } from "@/lib/sessions/session-service";
import { signJwtAccessToken } from "@/lib/tokens/jwt-access-token";
import { User } from "@/models/User";
import { TokenRejected, verifyAccessToken, verifyIdToken, verifyLogoutToken, type IdentityKeys } from "../docs/examples/verify-tokens";
import { createTestUser } from "./helpers";

const ISSUER = "http://localhost:3000";
const CLIENT = "noirly-crm";
const API = "https://api.crm.noirly.test";

let keys: IdentityKeys;
beforeEach(async () => {
  keys = { issuer: ISSUER, jwks: createLocalJWKSet(await getJwks()) };
});
/** Re-reads JWKS, as an app does after a rotation. */
const refreshKeys = async () => { keys = { issuer: ISSUER, jwks: createLocalJWKSet(await getJwks()) }; };

let count = 0;
async function signedIn(methods: Array<"password" | "totp"> = ["password"]) {
  const { user } = await createTestUser({ email: `u${(count += 1)}@example.com` });
  const { session } = await createSession({ userId: user._id, methods });
  return { user: (await User.findById(user._id))!, session };
}

async function idToken(opts: { clientId?: string; nonce?: string; authTime?: Date; methods?: Array<"password" | "totp"> } = {}) {
  const { user, session } = await signedIn(opts.methods);
  return createIdToken({ user, clientId: opts.clientId ?? CLIENT, scope: "openid email", nonce: opts.nonce ?? "n-123", authTime: opts.authTime ?? new Date(), methods: opts.methods ?? ["password"], sessionId: session._id });
}

async function accessToken(scope = "crm.read", audience = API) {
  const { user, session } = await signedIn();
  return signJwtAccessToken({ audience, clientId: CLIENT, userId: String(user._id), sessionId: session._id, scope, expiresIn: 600, authTime: new Date(), methods: ["password"] });
}

const rejected = (promise: Promise<unknown>) => expect(promise).rejects.toBeInstanceOf(TokenRejected);
const later = (seconds: number) => new Date(Date.now() + seconds * 1000);

describe("ID tokens", () => {
  it("pass every check when they're right", async () => {
    const payload = await verifyIdToken(await idToken(), { ...keys, clientId: CLIENT }, { nonce: "n-123", maxAgeSeconds: 300, acr: ["urn:noirly:acr:1fa", "urn:noirly:acr:mfa"] });
    expect(payload).toMatchObject({ iss: ISSUER, aud: CLIENT, nonce: "n-123" });
    expect(payload.sid).toBeTruthy();
  });

  it("are refused for another app, another issuer, or once expired", async () => {
    const token = await idToken();
    await rejected(verifyIdToken(token, { ...keys, clientId: "noirly-docs" }, { nonce: "n-123" }));
    await rejected(verifyIdToken(token, { ...keys, issuer: "https://auth.someone-else.test", clientId: CLIENT }, { nonce: "n-123" }));
    await rejected(verifyIdToken(token, { ...keys, issuer: `${ISSUER}/`, clientId: CLIENT }, { nonce: "n-123" }));
    await rejected(verifyIdToken(token, { ...keys, clientId: CLIENT, currentDate: later(getEnv().ACCESS_TOKEN_TTL_SECONDS + 120) }, { nonce: "n-123" }));
    // Within the minute of skew it still passes.
    await expect(verifyIdToken(token, { ...keys, clientId: CLIENT, currentDate: later(getEnv().ACCESS_TOKEN_TTL_SECONDS + 30) }, { nonce: "n-123" })).resolves.toBeTruthy();
    // Issued "in the future" for this verifier's clock.
    await rejected(verifyIdToken(token, { ...keys, clientId: CLIENT, currentDate: later(-300) }, { nonce: "n-123" }));
  });

  it("are refused with a different or missing nonce", async () => {
    await rejected(verifyIdToken(await idToken({ nonce: "someone-elses" }), { ...keys, clientId: CLIENT }, { nonce: "n-123" }));
    const { user, session } = await signedIn();
    const noNonce = await createIdToken({ user, clientId: CLIENT, scope: "openid", authTime: new Date(), sessionId: session._id });
    await rejected(verifyIdToken(noNonce, { ...keys, clientId: CLIENT }, { nonce: "n-123" }));
  });

  it("are refused when the sign-in is older than max_age, or weaker than asked", async () => {
    const old = await idToken({ authTime: new Date(Date.now() - 3600_000) });
    await rejected(verifyIdToken(old, { ...keys, clientId: CLIENT }, { nonce: "n-123", maxAgeSeconds: 600 }));
    await rejected(verifyIdToken(await idToken(), { ...keys, clientId: CLIENT }, { nonce: "n-123", acr: ["urn:noirly:acr:mfa"] }));
    await expect(verifyIdToken(await idToken({ methods: ["password", "totp"] }), { ...keys, clientId: CLIENT }, { nonce: "n-123", acr: ["urn:noirly:acr:mfa"] })).resolves.toBeTruthy();
  });
});

describe("forged and confused tokens", () => {
  it("refuses alg none, and HS256 keyed with Identity's public key", async () => {
    const claims = decodeJwt(await idToken());
    const unsigned = new UnsecuredJWT(claims).encode();
    await rejected(verifyIdToken(unsigned, { ...keys, clientId: CLIENT }, { nonce: "n-123" }));
    const hmac = await new SignJWT(claims).setProtectedHeader({ alg: "HS256", typ: "JWT" }).sign(new TextEncoder().encode(getEnv().JWT_PUBLIC_KEY));
    await rejected(verifyIdToken(hmac, { ...keys, clientId: CLIENT }, { nonce: "n-123" }));
  });

  it("refuses a changed payload, and a key Identity never published", async () => {
    const token = await idToken();
    const [header, , signature] = token.split(".");
    const forged = Buffer.from(JSON.stringify({ ...decodeJwt(token), sub: "000000000000000000000000" })).toString("base64url");
    await rejected(verifyIdToken(`${header}.${forged}.${signature}`, { ...keys, clientId: CLIENT }, { nonce: "n-123" }));

    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { type: "pkcs8", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });
    const strange = await new SignJWT(decodeJwt(token)).setProtectedHeader({ alg: "RS256", typ: "JWT", kid: "test-key-1" }).sign(await importPKCS8(privateKey, "RS256"));
    await rejected(verifyIdToken(strange, { ...keys, clientId: CLIENT }, { nonce: "n-123" }));
  });

  it("won't take one kind of token for another", async () => {
    const api = await accessToken();
    const { user } = await signedIn();
    const logout = await signLogoutToken({ clientId: CLIENT, sub: String(user._id), sid: "abc" });
    // An API token or a logout token isn't an ID token, even with the right aud.
    const apiForClient = await accessToken("crm.read", CLIENT);
    await rejected(verifyIdToken(apiForClient, { ...keys, clientId: CLIENT }));
    await rejected(verifyIdToken(logout, { ...keys, clientId: CLIENT }));
    // An ID token isn't an access token.
    await rejected(verifyAccessToken(await idToken({ clientId: API }), { ...keys, audience: API }));
    // Nor an API token a logout token.
    await rejected(verifyLogoutToken(api, { ...keys, clientId: API }, () => false));
  });

  it("keeps working across a key rotation, and stops for a key dropped after a leak", async () => {
    const before = await idToken();
    await rotateSigningKeys({ emergency: true });
    await refreshKeys();
    await expect(verifyIdToken(before, { ...keys, clientId: CLIENT }, { nonce: "n-123" })).resolves.toBeTruthy();
    const after = await idToken();
    await expect(verifyIdToken(after, { ...keys, clientId: CLIENT }, { nonce: "n-123" })).resolves.toBeTruthy();

    await rotateSigningKeys({ emergency: true, dropOld: true });
    await refreshKeys();
    // `after` was signed by the key just dropped; `before` by one still retiring.
    await rejected(verifyIdToken(after, { ...keys, clientId: CLIENT }, { nonce: "n-123" }));
    await expect(verifyIdToken(before, { ...keys, clientId: CLIENT }, { nonce: "n-123" })).resolves.toBeTruthy();
  });
});

describe("JWT access tokens at an API", () => {
  it("pass with the right audience and scope, and not otherwise", async () => {
    const token = await accessToken("crm.read crm.write");
    expect(await verifyAccessToken(token, { ...keys, audience: API }, ["crm.write"])).toMatchObject({ client_id: CLIENT, scope: "crm.read crm.write" });
    await rejected(verifyAccessToken(token, { ...keys, audience: "https://api.docs.noirly.test" }));
    await rejected(verifyAccessToken(await accessToken("crm.read"), { ...keys, audience: API }, ["crm.write"]));
    await rejected(verifyAccessToken(token, { ...keys, audience: API, currentDate: later(600 + 120) }));
  });
});

describe("back-channel logout tokens", () => {
  it("pass once, naming the session to end, and are refused when replayed", async () => {
    const { user } = await signedIn();
    const seen = new Set<string>();
    const remember = (jti: string) => (seen.has(jti) ? true : (seen.add(jti), false));
    const token = await signLogoutToken({ clientId: CLIENT, sub: String(user._id), sid: "sid-1" });
    expect(await verifyLogoutToken(token, { ...keys, clientId: CLIENT }, remember)).toEqual({ sub: String(user._id), sid: "sid-1" });
    await rejected(verifyLogoutToken(token, { ...keys, clientId: CLIENT }, remember));
    // Every session of the person: no sid.
    expect((await verifyLogoutToken(await signLogoutToken({ clientId: CLIENT, sub: String(user._id), sid: null }), { ...keys, clientId: CLIENT }, remember)).sid).toBeNull();
  });

  it("are refused for another app, or when it's really an ID token", async () => {
    const { user } = await signedIn();
    await rejected(verifyLogoutToken(await signLogoutToken({ clientId: CLIENT, sub: String(user._id), sid: "s" }), { ...keys, clientId: "noirly-docs" }, () => false));
    await rejected(verifyLogoutToken(await idToken(), { ...keys, clientId: CLIENT }, () => false));
  });
});
