import { Schema, models, model, type InferSchemaType, type Model, Types } from "mongoose";

const refreshTokenSchema = new Schema(
  {
    tokenHash: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    familyId: {
      type: String,
      required: true,
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
      index: true,
    },
    scope: { type: String, required: true },
    // APIs this grant covers (RFC 8707); a refresh can ask for a token for any of them.
    resources: { type: [String], default: [] },
    // Organization context: refreshes stay in it.
    organizationId: { type: Schema.Types.ObjectId, ref: "Organization", default: null },
    expiresAt: { type: Date, required: true },
    revokedAt: { type: Date, default: null },
    replacedByTokenHash: { type: String, default: null },
    reuseDetectedAt: { type: Date, default: null },
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
  },
);

refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export type RefreshTokenDocument = InferSchemaType<typeof refreshTokenSchema> & {
  _id: Types.ObjectId;
};

export const RefreshToken: Model<RefreshTokenDocument> =
  (models.RefreshToken as Model<RefreshTokenDocument>) ||
  model<RefreshTokenDocument>("RefreshToken", refreshTokenSchema);
