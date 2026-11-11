import { Schema, models, model, type InferSchemaType, type Model, type Types } from "mongoose";

/** One sign-in, for spotting unusual ones (lib/security/risk.ts). Kept a year. */
const signInRecordSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
    at: { type: Date, required: true, default: Date.now },
    deviceId: { type: String, default: null },
    // A short form of the browser (the user agent), when there's no device id.
    agent: { type: String, default: null },
    // Two-letter country code, from the edge (a hint, not proof).
    country: { type: String, default: null },
    signals: { type: [String], default: [] },
  },
  { timestamps: false },
);

signInRecordSchema.index({ userId: 1, at: -1 });
signInRecordSchema.index({ at: 1 }, { expireAfterSeconds: 365 * 86_400 });

export type SignInRecordDocument = InferSchemaType<typeof signInRecordSchema> & { _id: Types.ObjectId };

export const SignInRecord: Model<SignInRecordDocument> =
  (models.SignInRecord as Model<SignInRecordDocument>) || model<SignInRecordDocument>("SignInRecord", signInRecordSchema, "sign_in_records");
