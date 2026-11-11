import { Schema, models, model, type Model, type Types } from "mongoose";

/**
 * What became of a merged account: its old subject id and the one it now
 * belongs to, ids only. Kept for good, so an app that still holds the old
 * `sub` can be pointed at the new one; `pending` lists apps that haven't
 * accepted the notice yet (lib/account/merge-webhooks.ts).
 */
export type MergedAccountDocument = {
  _id: Types.ObjectId;
  fromSub: string;
  toSub: string;
  mergedAt: Date;
  pending: Array<{ clientId: string; attempts: number; lastError: string | null }>;
};

const mergedAccountSchema = new Schema<MergedAccountDocument>({
  fromSub: { type: String, required: true, unique: true },
  toSub: { type: String, required: true, index: true },
  mergedAt: { type: Date, required: true },
  pending: {
    type: [{ _id: false, clientId: { type: String, required: true }, attempts: { type: Number, default: 0 }, lastError: { type: String, default: null } }],
    default: [],
  },
});

export const MergedAccount: Model<MergedAccountDocument> =
  (models.MergedAccount as Model<MergedAccountDocument>) || model<MergedAccountDocument>("MergedAccount", mergedAccountSchema, "merged_accounts");
