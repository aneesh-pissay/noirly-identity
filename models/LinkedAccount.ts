import { Schema, models, model, type InferSchemaType, type Model, Types } from "mongoose";

const linkedAccountSchema = new Schema(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    provider: {
      type: String,
      required: true,
      enum: ["google", "apple", "microsoft", "github"],
      index: true,
    },
    providerAccountId: {
      type: String,
      required: true,
    },
    // The provider's address for it when linked, so settings can say which account it is.
    email: { type: String, default: null },
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
  },
);

linkedAccountSchema.index({ provider: 1, providerAccountId: 1 }, { unique: true });

export type LinkedAccountDocument = InferSchemaType<typeof linkedAccountSchema> & {
  _id: Types.ObjectId;
};

export const LinkedAccount: Model<LinkedAccountDocument> =
  (models.LinkedAccount as Model<LinkedAccountDocument>) ||
  model<LinkedAccountDocument>("LinkedAccount", linkedAccountSchema);
