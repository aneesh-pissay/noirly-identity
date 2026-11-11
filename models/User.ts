import {
  Schema,
  models,
  model,
  type InferSchemaType,
  type Model,
  type Types,
} from "mongoose";
import type { UserRole, UserStatus } from "@/types";
import { CONTRAST, MOTION, TEXT_SIZES } from "@/lib/account/preferences";

const userSchema = new Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    emailVerified: { type: Boolean, default: false },
    passwordHash: { type: String, default: null, select: false },
    firstName: { type: String, required: true, trim: true },
    lastName: { type: String, required: true, trim: true },
    displayName: { type: String, required: true, trim: true },
    avatarUrl: { type: String, default: null },
    phoneNumber: { type: String, default: null },
    // When the number was proved by a texted code (lib/account/phone.ts); null if it never was, or it changed since.
    phoneVerifiedAt: { type: Date, default: null },
    // Preferences apps follow (lib/account/preferences.ts); null means the device's own.
    locale: { type: String, default: null },
    zoneinfo: { type: String, default: null },
    accessibility: {
      type: new Schema(
        {
          motion: { type: String, enum: MOTION, default: "system" },
          contrast: { type: String, enum: CONTRAST, default: "system" },
          textSize: { type: String, enum: TEXT_SIZES, default: "default" },
        },
        { _id: false },
      ),
      default: null,
    },
    status: {
      type: String,
      enum: ["active", "disabled", "pending_verification"] satisfies UserStatus[],
      default: "pending_verification",
      index: true,
    },
    roles: {
      type: [String],
      enum: ["user", "admin"] satisfies UserRole[],
      default: ["user"],
    },
    lastLoginAt: { type: Date, default: null },
    // A second step is required at every sign-in (lib/security/factors.ts): the last factor can't be removed while it is.
    mfaRequired: { type: Boolean, default: false },
    // A space requires a second step and the account has none: until then it's a nudge, after that apps are closed (lib/security/enrollment.ts).
    mfaGraceUntil: { type: Date, default: null },
    // A sign-in found the password in known breaches (lib/security/breached-passwords.ts); cleared when it changes.
    passwordBreachedAt: { type: Date, default: null },
    // Locked (lib/security/containment.ts, lib/security/account-lock.ts): no sign-in of any kind until unlocked.
    lockedAt: { type: Date, default: null },
    lockReason: { type: String, default: null },
    lockedBy: { type: Schema.Types.ObjectId, ref: "User", default: null },
    // "self" (frozen by its owner, lib/security/account-lock.ts) or "admin".
    lockKind: { type: String, enum: ["self", "admin", "closing", "deprovisioned", null], default: null },
    // Deprovisioned by a space that owns the address's domain (lib/directory/lifecycle.ts); only it can reactivate.
    lockedByOrganization: { type: Schema.Types.ObjectId, ref: "Organization", default: null },
    // Closing (lib/account/closure.ts): deleted for good after this, unless undone.
    closingAt: { type: Date, default: null },
    deleteAfter: { type: Date, default: null },
    // A confirmed unfreeze takes effect at this time.
    unlockAt: { type: Date, default: null },
    // Contained after a takeover: the password was removed and a new one must be chosen.
    mustResetPassword: { type: Boolean, default: false },
    // A recovery address (lib/account/recovery-methods.ts): never used to sign in, never shown to apps.
    recoveryEmail: { type: String, default: null, lowercase: true, trim: true },
    recoveryEmailVerifiedAt: { type: Date, default: null },
    recoveryEmailCodeHash: { type: String, default: null },
    recoveryEmailCodeExpiresAt: { type: Date, default: null },
    // How long sessions last (lib/sessions/lifetime.ts); nulls mean Identity's defaults.
    sessionPolicy: {
      idleSeconds: { type: Number, default: null },
      absoluteSeconds: { type: Number, default: null },
    },
  },
  {
    timestamps: true,
  },
);

export type UserDocument = InferSchemaType<typeof userSchema> & {
  _id: Types.ObjectId;
  createdAt: Date;
  updatedAt: Date;
};

export const User: Model<UserDocument> =
  (models.User as Model<UserDocument>) ||
  model<UserDocument>("User", userSchema);
