import { Schema, models, model, type Model, type Types } from "mongoose";

/**
 * A key Identity signs tokens with (lib/oidc/keys.ts).
 * - `next`: published in JWKS ahead of use, so apps have it before it signs anything.
 * - `active`: signs everything. Exactly one.
 * - `retired`: no longer signs; published until `removeAfter`, when every token it signed has expired.
 */
export type SigningKeyState = "next" | "active" | "retired";

export type SigningKeyDocument = {
  _id: Types.ObjectId;
  kid: string;
  state: SigningKeyState;
  publicKeyPem: string;
  /** PKCS#8, sealed with ENCRYPTION_KEY (lib/security/encryption.ts), bound to the kid. */
  privateKeySealed: string;
  createdAt: Date;
  activatedAt: Date | null;
  retiredAt: Date | null;
  removeAfter: Date | null;
};

const signingKeySchema = new Schema<SigningKeyDocument>({
  kid: { type: String, required: true, unique: true },
  state: { type: String, enum: ["next", "active", "retired"], required: true, index: true },
  publicKeyPem: { type: String, required: true },
  privateKeySealed: { type: String, required: true, select: false },
  createdAt: { type: Date, default: Date.now },
  activatedAt: { type: Date, default: null },
  retiredAt: { type: Date, default: null },
  removeAfter: { type: Date, default: null },
});

export const SigningKey: Model<SigningKeyDocument> =
  (models.SigningKey as Model<SigningKeyDocument>) ||
  model<SigningKeyDocument>("SigningKey", signingKeySchema);
