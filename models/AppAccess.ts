import { Schema, models, model, type InferSchemaType, type Model, type Types } from "mongoose";

/**
 * One app's use of one account (lib/account/app-access.ts): what it has
 * been allowed to see, and when it first and last did. Tokens expire and
 * are cleaned away; this stays, so the account page can say which apps
 * have had its details even long after.
 */
const appAccessSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true },
    clientId: { type: String, required: true },
    // Every scope it has been granted, over time (since access was last removed).
    scopes: { type: [String], default: [] },
    // When each scope was first granted.
    grants: { type: [{ scope: { type: String, required: true }, at: { type: Date, required: true }, _id: false }], default: [] },
    // The person removed the app's access (lib/account/app-access.ts): hidden from the list until it's used again.
    removedAt: { type: Date, default: null },
    // After a removal the app must ask on the consent screen again, even if it normally doesn't.
    consentRequired: { type: Boolean, default: false },
    firstUsedAt: { type: Date, required: true },
    // A token issued, or details read through UserInfo.
    lastUsedAt: { type: Date, required: true },
  },
  { timestamps: false },
);

appAccessSchema.index({ userId: 1, clientId: 1 }, { unique: true });

export type AppAccessDocument = InferSchemaType<typeof appAccessSchema> & { _id: Types.ObjectId };

export const AppAccess: Model<AppAccessDocument> =
  (models.AppAccess as Model<AppAccessDocument>) || model<AppAccessDocument>("AppAccess", appAccessSchema, "app_access");
