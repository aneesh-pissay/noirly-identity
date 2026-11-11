import { Schema, models, model, type InferSchemaType, type Model, Types } from "mongoose";

const emailVerificationTokenSchema = new Schema(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    tokenHash: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    // The six-digit code in the same email (lib/security/email-code.ts), and wrong tries at it.
    codeHash: { type: String, default: null },
    attempts: { type: Number, default: 0 },
    // Set for an additional address (UserEmail); null for the account's primary one.
    addressId: { type: Schema.Types.ObjectId, ref: "UserEmail", default: null },
    expiresAt: { type: Date, required: true },
    usedAt: { type: Date, default: null },
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
  },
);

emailVerificationTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export type EmailVerificationTokenDocument = InferSchemaType<
  typeof emailVerificationTokenSchema
> & {
  _id: Types.ObjectId;
};

export const EmailVerificationToken: Model<EmailVerificationTokenDocument> =
  (models.EmailVerificationToken as Model<EmailVerificationTokenDocument>) ||
  model<EmailVerificationTokenDocument>(
    "EmailVerificationToken",
    emailVerificationTokenSchema,
  );
