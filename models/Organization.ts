import { Schema, models, model, type InferSchemaType, type Model, Types } from "mongoose";
import type { OrganizationStatus } from "@/types";

const organizationSchema = new Schema(
  {
    name: { type: String, required: true, trim: true },
    slug: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    // Every member must use a second step at sign-in (lib/security/factors.ts).
    requireMfa: { type: Boolean, default: false },
    // Security policies (lib/spaces/org-security.ts): how members must sign in to open apps here,
    // and how long their sessions may last (the strictest of theirs and every organization's).
    allowedMethods: { type: [String], default: [] },
    // Single sign-on (lib/federation/enforcement.ts): members at its IdPs' domains must sign in through them,
    // except these break-glass accounts (with a second step), for when the IdP is down.
    ssoEnforced: { type: Boolean, default: false },
    breakGlassUserIds: { type: [Schema.Types.ObjectId], ref: "User", default: [] },
    // Directory groups whose members are admins (lib/scim/groups.ts).
    scimAdminGroups: { type: [String], default: [] },
    sessionPolicy: {
      idleSeconds: { type: Number, default: null },
      absoluteSeconds: { type: Number, default: null },
    },
    // Which apps it uses and who may open them (lib/spaces/org-apps.ts).
    appsMode: { type: String, enum: ["open", "listed"], default: "open" },
    // For time conditions on access (lib/authz/conditions.ts); UTC without one.
    timeZone: { type: String, default: null },
    apps: {
      type: [
        new Schema(
          {
            appKey: { type: String, required: true },
            access: { type: String, enum: ["everyone", "admins", "teams"], default: "everyone" },
            teamIds: { type: [Schema.Types.ObjectId], default: [] },
          },
          { _id: false },
        ),
      ],
      default: [],
    },
    status: {
      type: String,
      enum: ["active", "disabled"] satisfies OrganizationStatus[],
      default: "active",
    },
  },
  {
    timestamps: true,
  },
);

export type OrganizationDocument = InferSchemaType<typeof organizationSchema> & {
  _id: Types.ObjectId;
};

export const Organization: Model<OrganizationDocument> =
  (models.Organization as Model<OrganizationDocument>) ||
  model<OrganizationDocument>("Organization", organizationSchema);
