import { Schema, models, model, type InferSchemaType, type Model, type Types } from "mongoose";

/**
 * The undo link sent to an account's old primary address when another
 * address takes its place (lib/account/emails.ts). Opening it within the
 * window puts the old address back and locks out whoever made the change.
 */
const emailChangeUndoSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
    from: { type: String, required: true },
    to: { type: String, required: true },
    tokenHash: { type: String, required: true, unique: true },
    expiresAt: { type: Date, required: true },
    usedAt: { type: Date, default: null },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

// Kept a day past expiry, so a late click says "expired" rather than "invalid".
emailChangeUndoSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 86_400 });

export type EmailChangeUndoDocument = InferSchemaType<typeof emailChangeUndoSchema> & { _id: Types.ObjectId };

export const EmailChangeUndo: Model<EmailChangeUndoDocument> =
  (models.EmailChangeUndo as Model<EmailChangeUndoDocument>) ||
  model<EmailChangeUndoDocument>("EmailChangeUndo", emailChangeUndoSchema, "email_change_undos");
