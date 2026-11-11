import { Schema, models, model, type Model, type Types } from "mongoose";

/**
 * An API that accepts Identity access tokens (RFC 8707 resource indicators,
 * lib/oauth/resources.ts). Apps ask for a token for it with `resource=<identifier>`
 * and get a JWT whose `aud` is the identifier, which the API verifies offline.
 */
export type ApiResourceDocument = {
  _id: Types.ObjectId;
  /** Absolute URI naming the API, such as https://api.crm.noirly.com. The token's `aud`. */
  identifier: string;
  name: string;
  /** Scopes the API defines (say, `crm.read`); granted ones go in its tokens. */
  scopes: Array<{ name: string; description: string }>;
  accessTokenTtlSeconds: number;
  /** Apps that may ask for tokens for it on someone's behalf. */
  allowedClientIds: string[];
  /**
   * Apps that may get tokens for it as themselves (the client credentials
   * grant), and the scopes each may have. Separate from `allowedClientIds`:
   * acting for a person and acting alone are different permissions.
   */
  machineGrants: Array<{ clientId: string; scopes: string[] }>;
  status: "active" | "disabled";
  createdAt: Date;
  updatedAt: Date;
};

const apiResourceSchema = new Schema<ApiResourceDocument>(
  {
    identifier: { type: String, required: true, unique: true },
    name: { type: String, required: true, trim: true },
    scopes: { type: [{ name: { type: String, required: true }, description: { type: String, default: "" }, _id: false }], default: [] },
    accessTokenTtlSeconds: { type: Number, default: 900 },
    allowedClientIds: { type: [String], default: [] },
    machineGrants: { type: [{ clientId: { type: String, required: true }, scopes: { type: [String], default: [] }, _id: false }], default: [] },
    status: { type: String, enum: ["active", "disabled"], default: "active" },
  },
  { timestamps: true },
);

export const ApiResource: Model<ApiResourceDocument> =
  (models.ApiResource as Model<ApiResourceDocument>) ||
  model<ApiResourceDocument>("ApiResource", apiResourceSchema);
