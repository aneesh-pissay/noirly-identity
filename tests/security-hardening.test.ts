import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { generate } from "otplib";
import { NextRequest } from "next/server";
import { beginTotp, confirmTotp, requireSecondFactor, verifyTotpOrRecovery } from "@/lib/security/mfa";
import { authenticatePasskey, authenticationOptions } from "@/lib/security/passkeys";
import { Mfa, Passkey, SecurityChallenge } from "@/models/SecurityCredential";
import { readJsonBody } from "@/lib/api/request";
import { rejectCrossOriginMutation, securePageResponse } from "@/lib/security/request";
import { consumeRateLimit } from "@/lib/security/shared-rate-limit";
import { createTestUser } from "./helpers";

describe("authenticator and recovery security", () => {
  it("encrypts enrollment secrets, requires confirmation and consumes recovery codes once", async () => {
    const { user } = await createTestUser();
    const id = String(user._id);
    const enrollment = await beginTotp(id, user.email);
    const pending = await Mfa.findOne({ userId: id }).lean();
    expect(pending?.pendingSecret).not.toContain(enrollment.secret);
    await expect(requireSecondFactor(id)).resolves.toBeUndefined();
    const code = await generate({ secret: enrollment.secret });
    const recovery = await confirmTotp(id, code);
    expect(recovery).toHaveLength(10);
    const enabled = await Mfa.findOne({ userId: id }).lean();
    expect(enabled?.recoveryHashes).not.toContain(recovery[0]);
    await expect(requireSecondFactor(id)).rejects.toMatchObject({ code: "mfa_required" });
    await expect(verifyTotpOrRecovery(id, code)).rejects.toMatchObject({ code: "invalid_code" });
    await verifyTotpOrRecovery(id, recovery[0]);
    await expect(verifyTotpOrRecovery(id, recovery[0])).rejects.toMatchObject({ code: "invalid_code" });
  });

  it("allows only one concurrent consumption of a recovery code", async () => {
    const { user } = await createTestUser();
    const id = String(user._id);
    const { secret } = await beginTotp(id, user.email);
    const codes = await confirmTotp(id, await generate({ secret }));
    const results = await Promise.allSettled([verifyTotpOrRecovery(id, codes[0]), verifyTotpOrRecovery(id, codes[0])]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
  });

  it("rejects expired enrollment", async () => {
    const { user } = await createTestUser();
    const { secret } = await beginTotp(String(user._id), user.email);
    await Mfa.updateOne({ userId: user._id }, { pendingExpiresAt: new Date(0) });
    await expect(confirmTotp(String(user._id), await generate({ secret }))).rejects.toMatchObject({ code: "invalid_enrollment" });
  });
});

// Fixed COSE EC2 map prefix followed by generated P-256 coordinates. No verifier mocks.
async function passkeyFixture() {
  const { user } = await createTestUser();
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  const publicKey = Buffer.concat([Buffer.from("a5010203262001215820", "hex"), Buffer.from(jwk.x!, "base64url"), Buffer.from("225820", "hex"), Buffer.from(jwk.y!, "base64url")]);
  const id = randomBytes(32).toString("base64url");
  await Passkey.create({ userId: user._id, credentialId: id, publicKey: publicKey.toString("base64url"), counter: 0 });
  const { options, token } = await authenticationOptions();
  function response(origin = "http://localhost:3000", flags = 5, challenge = options.challenge) {
    const client = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin, crossOrigin: false }));
    const auth = Buffer.concat([createHash("sha256").update("localhost").digest(), Buffer.from([flags, 0, 0, 0, 1])]);
    const signature = sign("sha256", Buffer.concat([auth, createHash("sha256").update(client).digest()]), pair.privateKey);
    return { id, rawId: id, type: "public-key" as const, clientExtensionResults: {}, response: { clientDataJSON: client.toString("base64url"), authenticatorData: auth.toString("base64url"), signature: signature.toString("base64url"), userHandle: Buffer.from(String(user._id)).toString("base64url") } };
  }
  return { user, token: token!, response };
}

describe("cryptographic passkey verification", () => {
  it("accepts a user-verified signature once and updates the counter", async () => {
    const { user, token, response } = await passkeyFixture();
    const verified = await authenticatePasskey(token, response());
    expect(String(verified.userId)).toBe(String(user._id));
    expect((await Passkey.findOne({ userId: user._id }).lean())?.counter).toBe(1);
    await expect(authenticatePasskey(token, response())).rejects.toMatchObject({ code: "invalid_challenge" });
  });
  it.each(["origin", "verification", "challenge", "signature"])("rejects invalid %s", async (kind) => {
    const { token, response } = await passkeyFixture();
    const payload = response(kind === "origin" ? "https://attacker.invalid" : undefined, kind === "verification" ? 1 : undefined, kind === "challenge" ? "wrong" : undefined);
    if (kind === "signature") payload.response.signature = randomBytes(72).toString("base64url");
    await expect(authenticatePasskey(token, payload)).rejects.toBeDefined();
    expect(await SecurityChallenge.countDocuments()).toBe(1);
  });
});

describe("request protections", () => {
  it("rejects multipart and oversized JSON bodies", async () => {
    await expect(readJsonBody(new NextRequest("http://localhost:3000/api/auth/login", { method: "POST", headers: { "content-type": "multipart/form-data" }, body: "file" }))).rejects.toMatchObject({ status: 415 });
    await expect(readJsonBody(new NextRequest("http://localhost:3000/api/auth/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ value: "x".repeat(256 * 1024) }) }))).rejects.toMatchObject({ status: 413 });
  });
  it("rejects cross-origin mutations and generates distinct CSP nonces", () => {
    const request = new NextRequest("http://localhost:3000/api/auth/login", { method: "POST", headers: { origin: "https://attacker.invalid" } });
    expect(rejectCrossOriginMutation(request)?.status).toBe(403);
    const first = securePageResponse(request).headers.get("content-security-policy");
    expect(first).toContain("script-src-attr 'none'");
    expect(first).toContain("'strict-dynamic'");
    expect(first).not.toBe(securePageResponse(request).headers.get("content-security-policy"));
  });
  it("enforces a shared limit under concurrent requests", async () => {
    const results = await Promise.all(Array.from({ length: 8 }, () => consumeRateLimit("concurrent-test", 3, 60)));
    expect(results.filter((r) => r.allowed)).toHaveLength(3);
  });
});
