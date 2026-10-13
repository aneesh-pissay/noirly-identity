import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse, type AuthenticationResponseJSON, type RegistrationResponseJSON, type AuthenticatorTransport } from "@simplewebauthn/server";
import { AppError } from "@/lib/api/errors";
import { getEnv } from "@/lib/config/env";
import { hashToken } from "@/lib/security/crypto";
import { checkFactorRate, newChallenge } from "@/lib/security/mfa";
import { Passkey, SecurityChallenge } from "@/models/SecurityCredential";

function relyingParty() {
  const origin = new URL(getEnv().APP_URL).origin;
  return { origin, id: new URL(origin).hostname };
}

export async function registrationOptions(userId: string, email: string, sessionId: string) {
  if (await Passkey.countDocuments({ userId }) >= 10) throw new AppError("You can save up to 10 passkeys", 400, "passkey_limit");
  const keys = await Passkey.find({ userId }).lean();
  const options = await generateRegistrationOptions({
    rpName: "Noirly Identity", rpID: relyingParty().id, userName: email,
    userID: new TextEncoder().encode(userId),
    attestationType: "none", authenticatorSelection: { residentKey: "required", userVerification: "required" },
    excludeCredentials: keys.map((key) => ({ id: key.credentialId, transports: key.transports as AuthenticatorTransport[] })),
  });
  const token = await newChallenge({ userId, sessionId, purpose: "register-passkey", challenge: options.challenge });
  return { options, token };
}

export async function registerPasskey(userId: string, sessionId: string, token: string, response: RegistrationResponseJSON, name: string) {
  const challenge = await SecurityChallenge.findOneAndDelete({ tokenHash: hashToken(token), userId, sessionId, purpose: "register-passkey", expiresAt: { $gt: new Date() } }).lean();
  if (!challenge?.challenge) throw new AppError("Passkey enrollment expired", 400, "invalid_challenge");
  const rp = relyingParty();
  const result = await verifyRegistrationResponse({ response, expectedChallenge: challenge.challenge, expectedOrigin: rp.origin, expectedRPID: rp.id, requireUserVerification: true });
  if (!result.verified || !result.registrationInfo) throw new AppError("Passkey could not be verified", 400, "invalid_passkey");
  const { credential } = result.registrationInfo;
  await Passkey.create({ userId, credentialId: credential.id, publicKey: Buffer.from(credential.publicKey).toString("base64url"), counter: credential.counter, transports: credential.transports ?? [], name });
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
  const options = await generateAuthenticationOptions({ rpID: relyingParty().id, userVerification: "required",
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
  const result = await verifyAuthenticationResponse({ response, expectedChallenge: challenge.challenge, expectedOrigin: rp.origin, expectedRPID: rp.id, requireUserVerification: true,
    credential: { id: key.credentialId, publicKey: new Uint8Array(Buffer.from(key.publicKey, "base64url")), counter: key.counter, transports: key.transports as AuthenticatorTransport[] },
  });
  if (!result.verified) throw new AppError("Passkey could not be verified", 401, "invalid_passkey");
  const consumed = await SecurityChallenge.findOneAndDelete({ _id: challenge._id, challenge: challenge.challenge, expiresAt: { $gt: new Date() } }).lean();
  if (!consumed) throw new AppError("Verification already used", 401, "invalid_challenge");
  const updated = await Passkey.updateOne({ _id: key._id, counter: key.counter }, { $set: { counter: result.authenticationInfo.newCounter } });
  if (updated.matchedCount !== 1) throw new AppError("Passkey state changed. Try again.", 401, "invalid_passkey");
  return { ...consumed, userId: key.userId };
}
