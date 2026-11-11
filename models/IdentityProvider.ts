import { Schema, models, model, type Model, type Types } from "mongoose";

/**
 * An organization's own identity provider (lib/federation): Entra ID, Okta or
 * any OIDC or SAML 2.0 IdP. People at its `domains` (verified domains of the
 * organization) sign in through it; with enforcement on, only through it.
 */
export type FederationProtocol = "oidc" | "saml";
export type FederationPreset = "generic" | "entra" | "okta";

export type SamlCertificate = { pem: string; fingerprint: string; notAfter: Date; alertedAt: Date | null };

export type AttributeMapping = {
  /** Claim or attribute names; empty uses the preset's. */
  email: string;
  firstName: string;
  lastName: string;
  groups: string;
  /** IdP group → organization role (admin wins over member; owners are never changed). */
  roles: Array<{ group: string; role: "admin" | "member" }>;
  /** IdP group → team; teams named here are kept in step with the groups. */
  teams: Array<{ group: string; teamId: Types.ObjectId }>;
};

export type IdentityProviderDocument = {
  _id: Types.ObjectId;
  organizationId: Types.ObjectId;
  name: string;
  protocol: FederationProtocol;
  preset: FederationPreset;
  enabled: boolean;
  domains: string[];
  /** Create accounts on first sign-in (just-in-time provisioning). */
  jit: boolean;
  oidc: {
    issuer: string;
    clientId: string;
    clientSecretSealed: string | null;
    authorizationEndpoint: string;
    tokenEndpoint: string;
    jwksUri: string;
    scopes: string[];
  } | null;
  saml: {
    idpEntityId: string;
    ssoUrl: string;
    metadataUrl: string | null;
    certificates: SamlCertificate[];
  } | null;
  mapping: AttributeMapping;
  lastUsedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
};

const schema = new Schema<IdentityProviderDocument>(
  {
    organizationId: { type: Schema.Types.ObjectId, ref: "Organization", required: true, index: true },
    name: { type: String, required: true, trim: true },
    protocol: { type: String, enum: ["oidc", "saml"], required: true },
    preset: { type: String, enum: ["generic", "entra", "okta"], default: "generic" },
    enabled: { type: Boolean, default: true },
    domains: { type: [String], default: [], index: true },
    jit: { type: Boolean, default: true },
    oidc: {
      type: new Schema(
        {
          issuer: String,
          clientId: String,
          clientSecretSealed: { type: String, default: null },
          authorizationEndpoint: String,
          tokenEndpoint: String,
          jwksUri: String,
          scopes: { type: [String], default: ["openid", "email", "profile"] },
        },
        { _id: false },
      ),
      default: null,
    },
    saml: {
      type: new Schema(
        {
          idpEntityId: String,
          ssoUrl: String,
          metadataUrl: { type: String, default: null },
          certificates: {
            type: [new Schema({ pem: String, fingerprint: String, notAfter: Date, alertedAt: { type: Date, default: null } }, { _id: false })],
            default: [],
          },
        },
        { _id: false },
      ),
      default: null,
    },
    mapping: {
      type: new Schema(
        {
          email: { type: String, default: "" },
          firstName: { type: String, default: "" },
          lastName: { type: String, default: "" },
          groups: { type: String, default: "" },
          roles: { type: [new Schema({ group: String, role: { type: String, enum: ["admin", "member"] } }, { _id: false })], default: [] },
          teams: { type: [new Schema({ group: String, teamId: Schema.Types.ObjectId }, { _id: false })], default: [] },
        },
        { _id: false },
      ),
      default: () => ({}),
    },
    lastUsedAt: { type: Date, default: null },
  },
  { timestamps: true },
);

export const IdentityProvider: Model<IdentityProviderDocument> =
  (models.IdentityProvider as Model<IdentityProviderDocument>) || model<IdentityProviderDocument>("IdentityProvider", schema, "identity_providers");

/** Who someone is at an IdP (its `sub` or SAML NameID), and their Noirly account. */
const federatedSchema = new Schema(
  {
    idpId: { type: Schema.Types.ObjectId, ref: "IdentityProvider", required: true },
    subject: { type: String, required: true },
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
    lastSignInAt: { type: Date, default: null },
  },
  { timestamps: true },
);
federatedSchema.index({ idpId: 1, subject: 1 }, { unique: true });

export type FederatedIdentityDocument = { _id: Types.ObjectId; idpId: Types.ObjectId; subject: string; userId: Types.ObjectId; lastSignInAt: Date | null };
export const FederatedIdentity: Model<FederatedIdentityDocument> =
  (models.FederatedIdentity as Model<FederatedIdentityDocument>) || model<FederatedIdentityDocument>("FederatedIdentity", federatedSchema, "federated_identities");

/** Replay protection for SAML: request ids sent, and assertion ids seen (node-saml's cache). */
const samlCacheSchema = new Schema({
  key: { type: String, required: true, unique: true },
  value: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true, index: { expireAfterSeconds: 0 } },
});
export const SamlCacheEntry: Model<{ key: string; value: string; createdAt: Date; expiresAt: Date }> =
  (models.SamlCacheEntry as never) || model("SamlCacheEntry", samlCacheSchema, "saml_cache");
