import { Schema, models, model, type InferSchemaType, type Model, type Types } from "mongoose";
import { IDENTITY_ACTIONS } from "@/lib/audit/chain";

/**
 * One event in the identity event log (lib/audit/chain.ts), chained to the
 * one before it in its stream by its hash. Events are only ever added:
 * changing or deleting one through the app throws, and doing it any other
 * way breaks the chain. The one way out is a whole account's stream at once,
 * when the account is deleted, with `{ eventPurge: true }`.
 */
const identityEventSchema = new Schema(
  {
    stream: { type: String, required: true },
    seq: { type: Number, required: true },
    at: { type: Date, required: true },
    action: { type: String, enum: IDENTITY_ACTIONS, required: true },
    // Who did it (null when it was the system or someone not signed in).
    actorId: { type: Schema.Types.ObjectId, ref: "User", default: null },
    // Whose account it's about.
    subjectId: { type: Schema.Types.ObjectId, ref: "User", default: null },
    clientId: { type: String, default: null },
    ipAddress: { type: String, default: null },
    userAgent: { type: String, default: null },
    data: { type: Schema.Types.Mixed, default: null },
    prevHash: { type: String, required: true },
    hash: { type: String, required: true },
  },
  { timestamps: false, minimize: false },
);

identityEventSchema.index({ stream: 1, seq: 1 }, { unique: true });
identityEventSchema.index({ action: 1, at: -1 });
identityEventSchema.index({ subjectId: 1, at: -1 });

function refuse(): never {
  throw new Error("Identity events can't be changed or deleted");
}

identityEventSchema.pre(["updateOne", "updateMany", "findOneAndUpdate", "replaceOne", "findOneAndReplace", "findOneAndDelete", "deleteOne"], refuse);
identityEventSchema.pre("deleteMany", function () {
  if (!this.getOptions().eventPurge) refuse();
});
identityEventSchema.pre("save", function () {
  if (!this.isNew) refuse();
});

export type IdentityEventDocument = InferSchemaType<typeof identityEventSchema> & { _id: Types.ObjectId };

export const IdentityEvent: Model<IdentityEventDocument> =
  (models.IdentityEvent as Model<IdentityEventDocument>) ||
  model<IdentityEventDocument>("IdentityEvent", identityEventSchema, "identity_events");
