import { Schema, models, model, type InferSchemaType, type Model, Types } from "mongoose";

const authorizationCodeSchema = new Schema(
  {
    codeHash: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    clientId: { type: String, required: true, index: true },
    userId: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    sessionId: {
      type: Schema.Types.ObjectId,
      ref: "Session",
      required: true,
    },
    redirectUri: { type: String, required: true },
    scope: { type: String, required: true },
    codeChallenge: { type: String, default: null },
    codeChallengeMethod: { type: String, enum: ["S256"], default: null },
    nonce: { type: String, default: null },
    authTime: { type: Date, required: true },
    // How the session was signed in, for the ID token's amr and acr.
    methods: { type: [String], default: [] },
    // RFC 8707: APIs the app may get tokens for with this grant (lib/oauth/resources.ts).
    resources: { type: [String], default: [] },
    // Organization context (lib/oauth/org-context.ts): tokens from this code are scoped to it.
    organizationId: { type: Schema.Types.ObjectId, ref: "Organization", default: null },
    expiresAt: { type: Date, required: true },
    usedAt: { type: Date, default: null },
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
  },
);

authorizationCodeSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export type AuthorizationCodeDocument = InferSchemaType<
  typeof authorizationCodeSchema
> & {
  _id: Types.ObjectId;
};

export const AuthorizationCode: Model<AuthorizationCodeDocument> =
  (models.AuthorizationCode as Model<AuthorizationCodeDocument>) ||
  model<AuthorizationCodeDocument>("AuthorizationCode", authorizationCodeSchema);
