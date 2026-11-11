import { Schema, models, model, type InferSchemaType, type Model, type Types } from "mongoose";

/**
 * An emailed sign-in link (lib/auth/magic-link.ts): single-use, short-lived,
 * and bound to the browser that asked for it by a secret kept in that
 * browser's cookie, so the link alone (forwarded, intercepted, opened by a
 * mail scanner) signs nobody in.
 */
const magicLinkSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
    tokenHash: { type: String, required: true, unique: true },
    browserHash: { type: String, required: true },
    returnTo: { type: String, default: "/account" },
    // The six-digit code in the same email (lib/security/email-code.ts), and wrong tries at it.
    codeHash: { type: String, default: null },
    attempts: { type: Number, default: 0 },
    expiresAt: { type: Date, required: true },
    usedAt: { type: Date, default: null },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

// Kept an hour past expiry, so a late click says "expired" rather than "invalid".
magicLinkSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 3600 });

export type MagicLinkDocument = InferSchemaType<typeof magicLinkSchema> & { _id: Types.ObjectId };

export const MagicLink: Model<MagicLinkDocument> =
  (models.MagicLink as Model<MagicLinkDocument>) || model<MagicLinkDocument>("MagicLink", magicLinkSchema, "magic_links");
