import { Schema, models, model, type InferSchemaType, type Model, type Types } from "mongoose";

/**
 * An email address on an account besides its primary one (which stays on
 * User.email). Unverified, it's only a claim: anyone may claim an address,
 * so it blocks nobody. Verified, it belongs to that account alone, and can
 * be made the primary address.
 */
const userEmailSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
    email: { type: String, required: true, lowercase: true, trim: true },
    verifiedAt: { type: Date, default: null },
  },
  { timestamps: true },
);

userEmailSchema.index({ userId: 1, email: 1 }, { unique: true });
// A verified address is one account's only.
userEmailSchema.index({ email: 1 }, { unique: true, partialFilterExpression: { verifiedAt: { $type: "date" } }, name: "one_verified_owner" });

export type UserEmailDocument = InferSchemaType<typeof userEmailSchema> & { _id: Types.ObjectId; createdAt: Date; updatedAt: Date };

export const UserEmail: Model<UserEmailDocument> =
  (models.UserEmail as Model<UserEmailDocument>) || model<UserEmailDocument>("UserEmail", userEmailSchema, "user_emails");
