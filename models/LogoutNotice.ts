import { Schema, models, model, type Model, type Types } from "mongoose";

/** A back-channel logout an app hasn't accepted yet (lib/oidc/backchannel-logout.ts). */
export type LogoutNoticeDocument = {
  _id: Types.ObjectId;
  clientId: string;
  sub: string;
  /** Null: every session of `sub` at that app. */
  sid: string | null;
  attempts: number;
  lastError: string | null;
  createdAt: Date;
};

const logoutNoticeSchema = new Schema<LogoutNoticeDocument>({
  clientId: { type: String, required: true },
  sub: { type: String, required: true },
  sid: { type: String, default: null },
  attempts: { type: Number, default: 1 },
  lastError: { type: String, default: null },
  createdAt: { type: Date, default: Date.now },
});

// After a day the app's tokens have long stopped working anyway; stop trying.
logoutNoticeSchema.index({ createdAt: 1 }, { expireAfterSeconds: 86_400 });

export const LogoutNotice: Model<LogoutNoticeDocument> =
  (models.LogoutNotice as Model<LogoutNoticeDocument>) ||
  model<LogoutNoticeDocument>("LogoutNotice", logoutNoticeSchema);
