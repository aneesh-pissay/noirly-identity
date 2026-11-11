import { Schema, models, model, type InferSchemaType, type Model, type Types } from "mongoose";

/**
 * A request to merge another account into this one (lib/account/merge.ts).
 * It goes: asked for by the account being kept → confirmed from a link sent
 * to the other account's address (proving it's the same person) → reviewed
 * and completed by the account being kept.
 */
const accountMergeSchema = new Schema(
  {
    keeperId: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
    // Null when no account has the address: the request still looks the same, so it can't be used to find out.
    sourceId: { type: Schema.Types.ObjectId, ref: "User", default: null, index: true },
    // The address as typed, for the review.
    sourceEmail: { type: String, required: true },
    tokenHash: { type: String, required: true, unique: true },
    status: { type: String, enum: ["awaiting_confirmation", "confirmed", "completed", "cancelled"], required: true },
    confirmedAt: { type: Date, default: null },
    completedAt: { type: Date, default: null },
    expiresAt: { type: Date, required: true },
  },
  { timestamps: true },
);

accountMergeSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 7 * 86_400 });

export type AccountMergeDocument = InferSchemaType<typeof accountMergeSchema> & { _id: Types.ObjectId; createdAt: Date };

export const AccountMerge: Model<AccountMergeDocument> =
  (models.AccountMerge as Model<AccountMergeDocument>) || model<AccountMergeDocument>("AccountMerge", accountMergeSchema, "account_merges");
