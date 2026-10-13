import { Schema, model, models, type InferSchemaType, type Model } from "mongoose";
const schema = new Schema({
  requestHash: { type: String, required: true, unique: true },
  pollHash: { type: String, required: true, unique: true },
  clientId: { type: String, required: true },
  scope: { type: String, required: true },
  displayCode: { type: String, required: true },
  userId: { type: Schema.Types.ObjectId, default: null },
  sessionId: { type: Schema.Types.ObjectId, default: null },
  expiresAt: { type: Date, required: true, index: { expireAfterSeconds: 0 } },
});
type Record = InferSchemaType<typeof schema>;
export const MobileBrowserLogin = (models.MobileBrowserLogin as Model<Record>) || model<Record>("MobileBrowserLogin", schema);
