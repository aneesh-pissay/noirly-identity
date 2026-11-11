import { Schema, models, model, type InferSchemaType, type Model, type Types } from "mongoose";
import { AVATAR_TYPES } from "@/lib/account/avatar-image";

/** An account's uploaded profile photo (lib/account/avatar.ts), small enough to keep in the database. */
const avatarSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true, unique: true },
    contentType: { type: String, enum: AVATAR_TYPES, required: true },
    data: { type: Buffer, required: true },
    // In the photo's address, so a new photo gets a new address and old copies can be cached for good.
    hash: { type: String, required: true },
    width: { type: Number, required: true },
    height: { type: Number, required: true },
  },
  { timestamps: true },
);

export type AvatarDocument = InferSchemaType<typeof avatarSchema> & { _id: Types.ObjectId };

export const Avatar: Model<AvatarDocument> =
  (models.Avatar as Model<AvatarDocument>) || model<AvatarDocument>("Avatar", avatarSchema, "avatars");
