import { Schema, model, models, type InferSchemaType, type Model } from "mongoose";

const mfaSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, required: true, unique: true },
  enabled: { type: Boolean, default: false },
  secret: { type: String, default: null },
  pendingSecret: { type: String, default: null },
  pendingExpiresAt: { type: Date, default: null },
  lastStep: { type: Number, default: -1 },
  recoveryHashes: { type: [String], default: [] },
  enabledAt: { type: Date, default: null },
  lastUsedAt: { type: Date, default: null },
});
type MfaRecord = InferSchemaType<typeof mfaSchema>;
export const Mfa = (models.Mfa as Model<MfaRecord>) || model<MfaRecord>("Mfa", mfaSchema);

const passkeySchema = new Schema({
  userId: { type: Schema.Types.ObjectId, required: true, index: true },
  credentialId: { type: String, required: true, unique: true },
  publicKey: { type: String, required: true },
  counter: { type: Number, required: true },
  name: { type: String, default: "Passkey" },
  transports: { type: [String], default: [] },
  // What it is (lib/security/authenticators.ts): a passkey, or a hardware security key.
  kind: { type: String, enum: ["passkey", "security_key"], default: "passkey" },
  aaguid: { type: String, default: null },
  attestationFormat: { type: String, default: null },
  synced: { type: Boolean, default: null },
  // Signs in on its own (stored on the key and checks a PIN or fingerprint); otherwise it's only a second step.
  standalone: { type: Boolean, default: true },
  lastUsedAt: { type: Date, default: null },
}, { timestamps: true });
type PasskeyRecord = InferSchemaType<typeof passkeySchema>;
export const Passkey = (models.Passkey as Model<PasskeyRecord>) || model<PasskeyRecord>("Passkey", passkeySchema);

const challengeSchema = new Schema({
  tokenHash: { type: String, required: true, unique: true },
  userId: { type: Schema.Types.ObjectId, default: null },
  purpose: { type: String, required: true },
  challenge: { type: String, default: null },
  clientId: { type: String, default: null },
  scope: { type: String, default: null },
  nonce: { type: String, default: null },
  sessionId: { type: Schema.Types.ObjectId, default: null },
  // Sign-in challenges: how the first step was passed (password, google), for the event log.
  method: { type: String, default: null },
  // Step-up (lib/auth/step-up.ts): the session being strengthened, and how it was signed in.
  stepUpSessionId: { type: Schema.Types.ObjectId, default: null },
  priorMethods: { type: [String], default: [] },
  // Adaptive second step for an account without one (lib/security/mfa.ts): a code emailed to it.
  emailCodeHash: { type: String, default: null },
  // Lost-factor recovery (lib/security/recovery.ts): the code sent to the account's recovery methods.
  recoveryCodeHash: { type: String, default: null },
  expiresAt: { type: Date, required: true, index: { expireAfterSeconds: 0 } },
});
type ChallengeRecord = InferSchemaType<typeof challengeSchema>;
export const SecurityChallenge = (models.SecurityChallenge as Model<ChallengeRecord>) || model<ChallengeRecord>("SecurityChallenge", challengeSchema);
