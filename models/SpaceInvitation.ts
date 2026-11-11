import { Schema, models, model, type InferSchemaType, type Model, type Types } from "mongoose";

/** An invitation to join a space (organization), by email, with a role (lib/spaces/invitations.ts). */
const spaceInvitationSchema = new Schema(
  {
    organizationId: { type: Schema.Types.ObjectId, ref: "Organization", required: true, index: true },
    email: { type: String, required: true, lowercase: true, trim: true },
    role: { type: String, enum: ["owner", "admin", "member"], required: true, default: "member" },
    // Only the hash: the link in the email is the secret.
    tokenHash: { type: String, required: true, unique: true },
    invitedBy: { type: Schema.Types.ObjectId, ref: "User", required: true },
    expiresAt: { type: Date, required: true },
    acceptedAt: { type: Date, default: null },
    acceptedBy: { type: Schema.Types.ObjectId, ref: "User", default: null },
    revokedAt: { type: Date, default: null },
    // Teams to join on accepting (CSV import, lib/directory/bulk.ts).
    teamIds: { type: [Schema.Types.ObjectId], default: [] },
  },
  { timestamps: true },
);

spaceInvitationSchema.index({ organizationId: 1, email: 1 });
// Long-finished invitations go after a while; pending ones expire on their own.
spaceInvitationSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 30 * 86_400 });

export type SpaceInvitationDocument = InferSchemaType<typeof spaceInvitationSchema> & { _id: Types.ObjectId };

export const SpaceInvitation: Model<SpaceInvitationDocument> =
  (models.SpaceInvitation as Model<SpaceInvitationDocument>) ||
  model<SpaceInvitationDocument>("SpaceInvitation", spaceInvitationSchema, "space_invitations");
