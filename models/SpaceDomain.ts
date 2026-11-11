import { Schema, models, model, type InferSchemaType, type Model, type Types } from "mongoose";

/** A business domain a space claims, proven by a DNS TXT record (lib/spaces/domains.ts). */
const spaceDomainSchema = new Schema(
  {
    organizationId: { type: Schema.Types.ObjectId, ref: "Organization", required: true, index: true },
    domain: { type: String, required: true, lowercase: true, trim: true },
    // Goes in the TXT record; not a secret, just proof of control.
    verificationToken: { type: String, required: true },
    verifiedAt: { type: Date, default: null },
    lastCheckedAt: { type: Date, default: null },
    // invite_only: claimed, joining still needs an invitation. auto_join: anyone with a confirmed address there may join.
    policy: { type: String, enum: ["invite_only", "auto_join"], default: "invite_only" },
  },
  { timestamps: true },
);

spaceDomainSchema.index({ organizationId: 1, domain: 1 }, { unique: true });
// One space per verified domain.
spaceDomainSchema.index({ domain: 1 }, { unique: true, partialFilterExpression: { verifiedAt: { $type: "date" } }, name: "one_verified_space" });

export type SpaceDomainDocument = InferSchemaType<typeof spaceDomainSchema> & { _id: Types.ObjectId };

export const SpaceDomain: Model<SpaceDomainDocument> =
  (models.SpaceDomain as Model<SpaceDomainDocument>) || model<SpaceDomainDocument>("SpaceDomain", spaceDomainSchema, "space_domains");
