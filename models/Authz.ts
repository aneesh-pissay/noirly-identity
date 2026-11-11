import { Schema, models, model, type InferSchemaType, type Model, type Types } from "mongoose";

/**
 * Authorization (lib/authz): roles an organization defines, who holds them,
 * requests for temporary extra access, and service accounts.
 */

/** A named set of permissions ("invoice:read", "invoice:*", "*"). */
const authzRoleSchema = new Schema(
  {
    organizationId: { type: Schema.Types.ObjectId, ref: "Organization", required: true, index: true },
    name: { type: String, required: true, trim: true },
    description: { type: String, default: "" },
    permissions: { type: [String], default: [] },
  },
  { timestamps: true },
);
authzRoleSchema.index({ organizationId: 1, name: 1 }, { unique: true });

/**
 * Someone (or a team, or a service account) holding a role in an
 * organization, on some resources, under some conditions, maybe until a time.
 */
const roleAssignmentSchema = new Schema(
  {
    organizationId: { type: Schema.Types.ObjectId, ref: "Organization", required: true, index: true },
    roleId: { type: Schema.Types.ObjectId, ref: "AuthzRole", required: true, index: true },
    subjectType: { type: String, enum: ["user", "team", "service"], required: true },
    subjectId: { type: Schema.Types.ObjectId, required: true, index: true },
    // Which resources: "*" for all, "project/*" for a kind, "project/42" for one.
    resource: { type: String, default: "*" },
    // Attribute-based conditions, all of which must hold (lib/authz/conditions.ts).
    conditions: {
      type: [new Schema({ attribute: { type: String, required: true }, op: { type: String, required: true }, value: { type: String, required: true } }, { _id: false })],
      default: [],
    },
    expiresAt: { type: Date, default: null },
    grantedBy: { type: Schema.Types.ObjectId, ref: "User", default: null },
    // "direct", or "elevation" when it came from an approved request for temporary access.
    source: { type: String, enum: ["direct", "elevation"], default: "direct" },
    reason: { type: String, default: "" },
  },
  { timestamps: true },
);

/** A request for a role for a while, waiting for an admin (lib/authz/elevation.ts). */
const accessRequestSchema = new Schema(
  {
    organizationId: { type: Schema.Types.ObjectId, ref: "Organization", required: true, index: true },
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
    roleId: { type: Schema.Types.ObjectId, ref: "AuthzRole", required: true },
    resource: { type: String, default: "*" },
    reason: { type: String, required: true },
    durationMinutes: { type: Number, required: true },
    status: { type: String, enum: ["pending", "approved", "denied", "cancelled"], default: "pending" },
    decidedBy: { type: Schema.Types.ObjectId, ref: "User", default: null },
    decidedAt: { type: Date, default: null },
    assignmentId: { type: Schema.Types.ObjectId, ref: "RoleAssignment", default: null },
  },
  { timestamps: true },
);

/** An organization's own non-human account: an OAuth client acting as itself, with roles (lib/authz/service-accounts.ts). */
const serviceAccountSchema = new Schema(
  {
    organizationId: { type: Schema.Types.ObjectId, ref: "Organization", required: true, index: true },
    name: { type: String, required: true, trim: true },
    clientId: { type: String, required: true, unique: true },
    createdBy: { type: Schema.Types.ObjectId, ref: "User", required: true },
    disabledAt: { type: Date, default: null },
  },
  { timestamps: true },
);
serviceAccountSchema.index({ organizationId: 1, name: 1 }, { unique: true });

export type AuthzRoleDocument = InferSchemaType<typeof authzRoleSchema> & { _id: Types.ObjectId };
export type RoleAssignmentDocument = InferSchemaType<typeof roleAssignmentSchema> & { _id: Types.ObjectId };
export type AccessRequestDocument = InferSchemaType<typeof accessRequestSchema> & { _id: Types.ObjectId };
export type ServiceAccountDocument = InferSchemaType<typeof serviceAccountSchema> & { _id: Types.ObjectId };

export const AuthzRole: Model<AuthzRoleDocument> =
  (models.AuthzRole as Model<AuthzRoleDocument>) || model<AuthzRoleDocument>("AuthzRole", authzRoleSchema, "authz_roles");
export const RoleAssignment: Model<RoleAssignmentDocument> =
  (models.RoleAssignment as Model<RoleAssignmentDocument>) || model<RoleAssignmentDocument>("RoleAssignment", roleAssignmentSchema, "authz_assignments");
export const AccessRequest: Model<AccessRequestDocument> =
  (models.AccessRequest as Model<AccessRequestDocument>) || model<AccessRequestDocument>("AccessRequest", accessRequestSchema, "authz_access_requests");
export const ServiceAccount: Model<ServiceAccountDocument> =
  (models.ServiceAccount as Model<ServiceAccountDocument>) || model<ServiceAccountDocument>("ServiceAccount", serviceAccountSchema, "authz_service_accounts");
