import { Schema, models, model, type InferSchemaType, type Model, type Types } from "mongoose";

/**
 * A request to remove an account's second steps because they've been lost
 * (lib/security/recovery.ts). It can be finished only after a waiting
 * period, by someone who passes the first sign-in step again, and anyone
 * with access to the account's addresses can cancel it before then.
 */
const factorRecoverySchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
    status: { type: String, enum: ["pending", "cancelled", "completed"], default: "pending" },
    // Proved with a code sent to a verified recovery method (shorter wait).
    verifiedByRecoveryMethod: { type: Boolean, default: false },
    // Started from somewhere risky (lib/security/risk.ts): an admin looks first.
    review: { type: String, enum: ["none", "pending", "approved", "denied"], default: "none" },
    reviewSignals: { type: [String], default: [] },
    reviewedBy: { type: Schema.Types.ObjectId, ref: "User", default: null },
    availableAt: { type: Date, required: true },
    cancelTokenHash: { type: String, required: true, unique: true },
    expiresAt: { type: Date, required: true },
  },
  { timestamps: true },
);

factorRecoverySchema.index({ expiresAt: 1 }, { expireAfterSeconds: 30 * 86_400 });

export type FactorRecoveryDocument = InferSchemaType<typeof factorRecoverySchema> & { _id: Types.ObjectId; createdAt: Date };

export const FactorRecovery: Model<FactorRecoveryDocument> =
  (models.FactorRecovery as Model<FactorRecoveryDocument>) || model<FactorRecoveryDocument>("FactorRecovery", factorRecoverySchema, "factor_recoveries");
