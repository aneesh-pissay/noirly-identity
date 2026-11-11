import { Schema, models, model, type InferSchemaType, type Model, Types } from "mongoose";

const accessTokenSchema = new Schema(
  {
    tokenHash: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    clientId: { type: String, required: true, index: true },
    // "machine": the client credentials grant (lib/oauth/client-credentials.ts), an app acting as itself,
    // with no person or session behind it.
    kind: { type: String, enum: ["user", "machine"], default: "user" },
    userId: {
      type: Schema.Types.ObjectId,
      ref: "User",
      default: null,
      index: true,
    },
    sessionId: {
      type: Schema.Types.ObjectId,
      ref: "Session",
      default: null,
      index: true,
    },
    scope: { type: String, required: true },
    // Set for a JWT access token for an API (RFC 8707): its `aud`. Identity's own endpoints refuse these.
    audience: { type: String, default: null },
    // Organization context: UserInfo and introspection answer for it.
    organizationId: { type: Schema.Types.ObjectId, ref: "Organization", default: null },
    expiresAt: { type: Date, required: true },
    revokedAt: { type: Date, default: null },
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
  },
);

accessTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export type AccessTokenDocument = InferSchemaType<typeof accessTokenSchema> & {
  _id: Types.ObjectId;
};

export const AccessToken: Model<AccessTokenDocument> =
  (models.AccessToken as Model<AccessTokenDocument>) ||
  model<AccessTokenDocument>("AccessToken", accessTokenSchema);
