import { Schema, models, model, type Model, type Types } from "mongoose";

/**
 * A tombstone for a deleted account: only the opaque subject id, never the
 * email or name. It exists so product apps that were offline when the account
 * was deleted still get the "account deleted" notice on a later retry
 * (`npm run account:retry-deletions`). Removed once every app has it.
 */
export type DeletedAccountDocument = {
  _id: Types.ObjectId;
  sub: string;
  deletedAt: Date;
  /** Apps (OAuth client ids) still waiting for the notice. */
  pending: Array<{ clientId: string; attempts: number; lastError: string | null }>;
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
});

export const DeletedAccount: Model<DeletedAccountDocument> =
  (models.DeletedAccount as Model<DeletedAccountDocument>) ||
  model<DeletedAccountDocument>("DeletedAccount", deletedAccountSchema);
