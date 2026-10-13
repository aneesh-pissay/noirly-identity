import { Schema, model, models, type InferSchemaType, type Model } from "mongoose";

const mfaSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, required: true, unique: true },
  enabled: { type: Boolean, default: false },
  secret: { type: String, default: null },
  pendingSecret: { type: String, default: null },
  pendingExpiresAt: { type: Date, default: null },
  lastStep: { type: Number, default: -1 },
  recoveryHashes: { type: [String], default: [] },
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
  expiresAt: { type: Date, required: true, index: { expireAfterSeconds: 0 } },
});
type ChallengeRecord = InferSchemaType<typeof challengeSchema>;
export const SecurityChallenge = (models.SecurityChallenge as Model<ChallengeRecord>) || model<ChallengeRecord>("SecurityChallenge", challengeSchema);
