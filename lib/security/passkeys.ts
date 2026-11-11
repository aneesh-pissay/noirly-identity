import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse, type AuthenticationResponseJSON, type RegistrationResponseJSON, type AuthenticatorTransport } from "@simplewebauthn/server";
import { AppError } from "@/lib/api/errors";
import { getEnv } from "@/lib/config/env";
import { hashToken } from "@/lib/security/crypto";
import { checkFactorRate, newChallenge } from "@/lib/security/mfa";
import { Passkey, SecurityChallenge } from "@/models/SecurityCredential";
import type { AuthenticatorKind } from "@/lib/security/authenticators";

function relyingParty() {
  const origin = new URL(getEnv().APP_URL).origin;
  return { origin, id: new URL(origin).hostname };
}

const REGISTER_PURPOSE: Record<AuthenticatorKind, string> = { passkey: "register-passkey", security_key: "register-security-key" };

/**
 * Options for adding a passkey (any authenticator, stored on it, checking a
 * PIN or fingerprint: a whole sign-in) or a hardware security key (one you
 * plug in or tap, asked for an attestation of its model; a key that can't
 * check a PIN, or can't store the credential, is kept as a second step only).
 */
export async function registrationOptions(userId: string, email: string, sessionId: string, kind: AuthenticatorKind = "passkey") {
  if (await Passkey.countDocuments({ userId }) >= 10) throw new AppError("You can save up to 10 passkeys and security keys", 400, "passkey_limit");
  const keys = await Passkey.find({ userId }).lean();
  const options = await generateRegistrationOptions({
    rpName: "Noirly Identity", rpID: relyingParty().id, userName: email,
    userID: new TextEncoder().encode(userId),
    ...(kind === "security_key"
      ? { attestationType: "direct" as const, authenticatorSelection: { authenticatorAttachment: "cross-platform" as const, residentKey: "preferred" as const, userVerification: "preferred" as const } }
      : { attestationType: "none" as const, authenticatorSelection: { residentKey: "required" as const, userVerification: "required" as const } }),
    extensions: { credProps: true },
    excludeCredentials: keys.map((key) => ({ id: key.credentialId, transports: key.transports as AuthenticatorTransport[] })),
  });
  const token = await newChallenge({ userId, sessionId, purpose: REGISTER_PURPOSE[kind], challenge: options.challenge });
  return { options, token };
}

export async function registerPasskey(userId: string, sessionId: string, token: string, response: RegistrationResponseJSON, name: string): Promise<{ kind: AuthenticatorKind; standalone: boolean }> {
  const challenge = await SecurityChallenge.findOneAndDelete({ tokenHash: hashToken(token), userId, sessionId, purpose: { $in: Object.values(REGISTER_PURPOSE) }, expiresAt: { $gt: new Date() } }).lean();
  if (!challenge?.challenge) throw new AppError("Passkey enrollment expired", 400, "invalid_challenge");
  const kind: AuthenticatorKind = challenge.purpose === REGISTER_PURPOSE.security_key ? "security_key" : "passkey";
  const rp = relyingParty();
  const result = await verifyRegistrationResponse({ response, expectedChallenge: challenge.challenge, expectedOrigin: rp.origin, expectedRPID: rp.id, requireUserVerification: kind === "passkey" });
  if (!result.verified || !result.registrationInfo) throw new AppError("Passkey could not be verified", 400, "invalid_passkey");
  const info = result.registrationInfo;
  // Stored on the key (discoverable) and verifying the person: then it signs in by itself.
  const discoverable = (response.clientExtensionResults as { credProps?: { rk?: boolean } } | undefined)?.credProps?.rk;
  const standalone = kind === "passkey" || (info.userVerified && discoverable === true);
  await Passkey.create({
    userId,
    credentialId: info.credential.id,
    publicKey: Buffer.from(info.credential.publicKey).toString("base64url"),
    counter: info.credential.counter,
    transports: info.credential.transports ?? [],
    name,
    kind,
    aaguid: info.aaguid ?? null,
    attestationFormat: info.fmt ?? null,
    synced: info.credentialDeviceType === "multiDevice",
    standalone,
  });
  return { kind, standalone };
}

export async function authenticationOptions(token?: string) {
  let userId: string | undefined;
  let current = token;
  if (token) {
    const existing = await SecurityChallenge.findOne({ tokenHash: hashToken(token), purpose: "login-mfa", expiresAt: { $gt: new Date() } }).lean();
    if (!existing?.userId) throw new AppError("Verification expired. Sign in again.", 401, "invalid_challenge");
    userId = existing.userId.toString();
  }
  const keys = userId ? await Passkey.find({ userId }).lean() : [];
  if (userId && !keys.length) throw new AppError("No passkey is registered. Use your authenticator or recovery code.", 400, "no_passkey");
  // As a second step (after a password or a provider) any registered key will do; on its own it must verify the person.
  const options = await generateAuthenticationOptions({ rpID: relyingParty().id, userVerification: userId ? "preferred" : "required",
    ...(userId ? { allowCredentials: keys.map((key) => ({ id: key.credentialId, transports: key.transports as AuthenticatorTransport[] })) } : {}),
  });
  if (current) await SecurityChallenge.updateOne({ tokenHash: hashToken(current), purpose: "login-mfa" }, { $set: { challenge: options.challenge } });
  else current = await newChallenge({ purpose: "passkey-login", challenge: options.challenge });
  return { options, token: current };
}

/** Returns a consumed, verified challenge with its credential owner. */
export async function authenticatePasskey(token: string, response: AuthenticationResponseJSON) {
  const challenge = await SecurityChallenge.findOne({ tokenHash: hashToken(token), purpose: { $in: ["login-mfa", "passkey-login"] }, expiresAt: { $gt: new Date() } }).lean();
  if (!challenge?.challenge) throw new AppError("Verification expired", 401, "invalid_challenge");
  const key = await Passkey.findOne({ credentialId: response.id }).lean();
  if (!key || (challenge.userId && !challenge.userId.equals(key.userId))) throw new AppError("Passkey not recognized", 401, "invalid_passkey");
  await checkFactorRate(key.userId.toString());
  const rp = relyingParty();
  // Signing in with a key alone needs it to verify the person, and to be one that can.
  const alone = challenge.purpose === "passkey-login";
  if (alone && key.standalone === false) throw new AppError("This security key works as a second step only. Sign in another way first.", 401, "second_step_only");
  const result = await verifyAuthenticationResponse({ response, expectedChallenge: challenge.challenge, expectedOrigin: rp.origin, expectedRPID: rp.id, requireUserVerification: alone,
    credential: { id: key.credentialId, publicKey: new Uint8Array(Buffer.from(key.publicKey, "base64url")), counter: key.counter, transports: key.transports as AuthenticatorTransport[] },
  });
  if (!result.verified) throw new AppError("Passkey could not be verified", 401, "invalid_passkey");
  const consumed = await SecurityChallenge.findOneAndDelete({ _id: challenge._id, challenge: challenge.challenge, expiresAt: { $gt: new Date() } }).lean();
  if (!consumed) throw new AppError("Verification already used", 401, "invalid_challenge");
  const updated = await Passkey.updateOne({ _id: key._id, counter: key.counter }, { $set: { counter: result.authenticationInfo.newCounter, lastUsedAt: new Date() } });
  if (updated.matchedCount !== 1) throw new AppError("Passkey state changed. Try again.", 401, "invalid_passkey");
  return { ...consumed, userId: key.userId };
}
