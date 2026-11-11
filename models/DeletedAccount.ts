import { Schema, models, model, type Model, type Types } from "mongoose";

/**
 * A tombstone for a deleted account: only the opaque subject id, never the
 * email or name. It exists so product apps that were offline when the account
 * was deleted still get the "account deleted" notice on a later retry
 * (`npm run account:retry-deletions`). Kept 90 days after the deletion so
 * admins can see which apps confirmed it (lib/account/deletion-status.ts).
 */
export type DeletedAccountDocument = {
  _id: Types.ObjectId;
  sub: string;
  deletedAt: Date;
  /** Apps (OAuth client ids) still waiting for the notice. */
  pending: Array<{ clientId: string; attempts: number; lastError: string | null }>;
  /** Apps that confirmed (answered 2xx), and when. */
  delivered: Array<{ clientId: string; at: Date }>;
  /** Apps that never confirmed after every retry. */
  failed: Array<{ clientId: string; attempts: number; lastError: string | null }>;
  keepUntil: Date;
};

const deletedAccountSchema = new Schema<DeletedAccountDocument>({
  sub: { type: String, required: true, unique: true, index: true },
  deletedAt: { type: Date, required: true },
  pending: {
    type: [
      {
        _id: false,
        clientId: { type: String, required: true },
        attempts: { type: Number, default: 0 },
        lastError: { type: String, default: null },
      },
    ],
    default: [],
  },
  delivered: { type: [{ _id: false, clientId: { type: String, required: true }, at: { type: Date, required: true } }], default: [] },
  failed: { type: [{ _id: false, clientId: { type: String, required: true }, attempts: { type: Number, default: 0 }, lastError: { type: String, default: null } }], default: [] },
  keepUntil: { type: Date, required: true, index: { expireAfterSeconds: 0 } },
});

export const DeletedAccount: Model<DeletedAccountDocument> =
  (models.DeletedAccount as Model<DeletedAccountDocument>) ||
  model<DeletedAccountDocument>("DeletedAccount", deletedAccountSchema);
