import { Schema, models, model, type InferSchemaType, type Model, type Types } from "mongoose";

/** A code texted to a phone number to prove it's the account's (lib/account/phone.ts). */
const phoneVerificationSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
    phone: { type: String, required: true },
    codeHash: { type: String, required: true },
    attempts: { type: Number, default: 0 },
    expiresAt: { type: Date, required: true },
    usedAt: { type: Date, default: null },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

phoneVerificationSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 3600 });

export type PhoneVerificationDocument = InferSchemaType<typeof phoneVerificationSchema> & { _id: Types.ObjectId; createdAt: Date };

export const PhoneVerification: Model<PhoneVerificationDocument> =
  (models.PhoneVerification as Model<PhoneVerificationDocument>) ||
  model<PhoneVerificationDocument>("PhoneVerification", phoneVerificationSchema, "phone_verifications");
