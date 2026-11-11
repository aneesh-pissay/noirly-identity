import { Schema, models, model, type InferSchemaType, type Model, Types } from "mongoose";
import type { OrganizationRole } from "@/types";

const organizationMembershipSchema = new Schema(
  {
    organizationId: {
      type: Schema.Types.ObjectId,
      ref: "Organization",
      required: true,
      index: true,
    },
    userId: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    role: {
      type: String,
      enum: ["owner", "admin", "member"] satisfies OrganizationRole[],
      required: true,
      default: "member",
    },
    // Delegated administration (lib/spaces/space-service.ts): null lets an admin do
    // everything admins can; a list limits them to those areas.
    adminAreas: { type: [String], enum: ["members", "settings", "domains", "apps", "access"], default: undefined },
    // What the organization knows about the member, for access conditions (lib/authz/conditions.ts): department, region…
    attributes: { type: Map, of: String, default: undefined },
    // SCIM (lib/scim): the directory's id for this person, when provisioned from one.
    scimExternalId: { type: String, default: null },
  },
  {
    timestamps: true,
  },
);

organizationMembershipSchema.index(
  { organizationId: 1, userId: 1 },
  { unique: true },
);

export type OrganizationMembershipDocument = InferSchemaType<
  typeof organizationMembershipSchema
> & {
  _id: Types.ObjectId;
};

export const OrganizationMembership: Model<OrganizationMembershipDocument> =
  (models.OrganizationMembership as Model<OrganizationMembershipDocument>) ||
  model<OrganizationMembershipDocument>(
    "OrganizationMembership",
    organizationMembershipSchema,
  );
