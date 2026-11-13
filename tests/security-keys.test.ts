import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { Types } from "mongoose";
import { assertKeepsAWayIn, listSignInMethods } from "@/lib/account/identities";
import { authenticatorModel, describeAuthenticator } from "@/lib/security/authenticators";
import { requireSecondFactor } from "@/lib/security/mfa";
import { authenticatePasskey, authenticationOptions, registrationOptions } from "@/lib/security/passkeys";
import { LinkedAccount } from "@/models/LinkedAccount";
import { Passkey } from "@/models/SecurityCredential";
import { User } from "@/models/User";
import { createAuthedSession, createTestUser } from "./helpers";

/** A key whose signatures we can make: flags 5 = present and verified, 1 = present only (no PIN). */
async function keyFor(userId: Types.ObjectId, standalone: boolean) {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  const publicKey = Buffer.concat([Buffer.from("a5010203262001215820", "hex"), Buffer.from(jwk.x!, "base64url"), Buffer.from("225820", "hex"), Buffer.from(jwk.y!, "base64url")]);
  const id = randomBytes(32).toString("base64url");
  await Passkey.create({ userId, credentialId: id, publicKey: publicKey.toString("base64url"), counter: 0, kind: "security_key", standalone });
  return (challenge: string, flags: number) => {
    const client = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin: "http://localhost:3000", crossOrigin: false }));
    const auth = Buffer.concat([createHash("sha256").update("localhost").digest(), Buffer.from([flags, 0, 0, 0, 1])]);
    const signature = sign("sha256", Buffer.concat([auth, createHash("sha256").update(client).digest()]), pair.privateKey);
    return { id, rawId: id, type: "public-key" as const, clientExtensionResults: {}, response: { clientDataJSON: client.toString("base64url"), authenticatorData: auth.toString("base64url"), signature: signature.toString("base64url") } };
  };
}

describe("what a key is", () => {
  it("names well-known authenticators and says what it can do", () => {
    expect(authenticatorModel("cb69481e-8ff7-4039-93ec-0a2729a154a8")).toBe("YubiKey 5 Series");
    expect(authenticatorModel("00000000-0000-0000-0000-000000000000")).toBeNull();
    expect(describeAuthenticator({ kind: "security_key", aaguid: "fa2b99dc-9e39-4257-8f92-4a30d23c4118", attestationFormat: "packed", synced: false, standalone: false })).toEqual({
      kindLabel: "Security key",
      model: "YubiKey 5 Series with NFC",
      attested: true,
      notes: ["Stays on the key", "Second step only", "Attested by the device (packed)"],
    });
    expect(describeAuthenticator({ kind: "passkey", aaguid: "fbfc3007-154e-4ecc-8c0b-6e020557d7bd", attestationFormat: "none", synced: true })).toMatchObject({ model: "iCloud Keychain", attested: false, notes: ["Synced across your devices"] });
  });
});

describe("security keys", () => {
  it("are asked for as a plug-in key, with an attestation, without demanding a PIN", async () => {
    const { user } = await createTestUser();
    const { session } = await createAuthedSession(String(user._id));
    const key = await registrationOptions(String(user._id), user.email, String(session._id), "security_key");
    expect(key.options).toMatchObject({ attestation: "direct", authenticatorSelection: { authenticatorAttachment: "cross-platform", residentKey: "preferred", userVerification: "preferred" }, extensions: { credProps: true } });
    const passkey = await registrationOptions(String(user._id), user.email, String(session._id), "passkey");
    expect(passkey.options).toMatchObject({ attestation: "none", authenticatorSelection: { residentKey: "required", userVerification: "required" } });
  });

  it("work as a second step without a PIN, but not on their own", async () => {
    const { user } = await createTestUser();
    const respond = await keyFor(user._id, false);
    // On its own: refused.
    const alone = await authenticationOptions();
    await expect(authenticatePasskey(alone.token!, respond(alone.options.challenge, 5))).rejects.toMatchObject({ code: "second_step_only" });
    // After a password: a touch is enough.
    const challenge = await requireSecondFactor(String(user._id), undefined, "password").catch((error: { details: { challenge: string } }) => error.details.challenge);
    const step = await authenticationOptions(challenge as string);
    expect(step.options.userVerification).toBe("preferred");
    const verified = await authenticatePasskey(step.token!, respond(step.options.challenge, 1));
    expect(String(verified.userId)).toBe(String(user._id));
    expect((await Passkey.findOne({ userId: user._id }).lean())!.lastUsedAt).toBeInstanceOf(Date);
  });

  it("don't count as a way in when they can only be a second step", async () => {
    const user = await User.create({ email: "keys@example.com", passwordHash: null, firstName: "K", lastName: "Y", displayName: "K Y", emailVerified: true, status: "active" });
    await LinkedAccount.create({ userId: user._id, provider: "google", providerAccountId: "g-keys" });
    await keyFor(user._id, false);
    expect((await listSignInMethods(String(user._id))).passkeys).toBe(0);
    // A second-step-only key is no way in, so the one key that signs in by itself can't go.
    await keyFor(user._id, true);
    await expect(assertKeepsAWayIn(String(user._id), { passkeys: 1 })).rejects.toMatchObject({ code: "last_sign_in_method" });
  });
});
