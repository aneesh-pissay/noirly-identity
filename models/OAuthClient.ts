import { Schema, models, model, type Model, type Types } from "mongoose";
import type { ClientStatus, ClientType, Scope } from "@/types";

export type OAuthClientDocument = {
  _id: Types.ObjectId;
  clientId: string;
  /** The app this client is one environment of (lib/oauth/environments.ts); its production client_id. */
  appKey?: string | null;
  environment?: "production" | "staging" | "development" | null;
  /** People who manage this app besides admins (lib/oauth/app-owners.ts). */
  ownerIds?: Types.ObjectId[];
  /** Set for an organization's service account (lib/authz/service-accounts.ts): it never signs people in. */
  serviceAccountOf?: Types.ObjectId | null;
  /** Who may use it (lib/oauth/access-policy.ts). */
  accessPolicy?: { mode: "anyone" | "spaces" | "allowlist"; spaceIds: Types.ObjectId[]; userIds: Types.ObjectId[] } | null;
  clientSecretHash?: string | null;
  /**
   * The secret before the last rotation, still accepted until
   * `previousSecretExpiresAt` so a deployed app can switch over without
   * downtime (lib/oauth/client-admin.ts).
   */
  previousSecretHash?: string | null;
  previousSecretExpiresAt?: Date | null;
  /** When an app last signed in with the previous secret: still in use? */
  previousSecretLastUsedAt?: Date | null;
  name: string;
  description: string;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  allowedScopes: Scope[];
  clientType: ClientType;
  status: ClientStatus;
  requirePkce: boolean;
  requireConsent: boolean;
  /** Every sign-in to this app needs a second step (app/api/oauth/authorize). */
  requireMfa: boolean;
  androidSha1Fingerprints: string[];
  /** Back-channel logout: Identity POSTs a logout token here when a session that reached the app ends. */
  backchannelLogoutUri?: string | null;
  /** Front-channel logout: loaded in a hidden frame when someone signs out in the browser. */
  frontchannelLogoutUri?: string | null;
  /** Personal data export (lib/account/data-export.ts): Identity asks here for one person's data. */
  dataExportUri?: string | null;
  /** Lifecycle webhooks (lib/webhooks/lifecycle.ts): where, and which events (empty: all). */
  lifecycleWebhookUri?: string | null;
  lifecycleEvents?: string[];
  createdAt: Date;
  updatedAt: Date;
};

const oauthClientSchema = new Schema<OAuthClientDocument>(
  {
    clientId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    appKey: { type: String, default: null, index: true },
    ownerIds: { type: [Schema.Types.ObjectId], ref: "User", default: [], index: true },
    serviceAccountOf: { type: Schema.Types.ObjectId, ref: "Organization", default: null },
    accessPolicy: {
      type: new Schema(
        {
          mode: { type: String, enum: ["anyone", "spaces", "allowlist"], default: "anyone" },
          spaceIds: { type: [Schema.Types.ObjectId], ref: "Organization", default: [] },
          userIds: { type: [Schema.Types.ObjectId], ref: "User", default: [] },
        },
        { _id: false },
      ),
      default: null,
    },
    environment: { type: String, enum: ["production", "staging", "development", null], default: null },
    clientSecretHash: {
      type: String,
      default: null,
      select: false,
    },
    previousSecretHash: { type: String, default: null, select: false },
    previousSecretExpiresAt: { type: Date, default: null },
    previousSecretLastUsedAt: { type: Date, default: null },
    name: { type: String, required: true, trim: true },
    description: { type: String, default: "" },
    redirectUris: {
      type: [String],
      required: true,
      validate: {
        validator: (uris: string[]) => uris.length > 0,
        message: "At least one redirect URI is required",
      },
    },
    postLogoutRedirectUris: {
      type: [String],
      default: [],
    },
    allowedScopes: {
      type: [String],
      default: ["openid", "profile", "email"],
    },
    clientType: {
      type: String,
      enum: ["public", "confidential"],
      required: true,
    },
    status: {
      type: String,
      enum: ["active", "disabled"],
      default: "active",
      index: true,
    },
    requirePkce: { type: Boolean, default: true },
    requireConsent: { type: Boolean, default: true },
    requireMfa: { type: Boolean, default: false },
    backchannelLogoutUri: { type: String, default: null },
    frontchannelLogoutUri: { type: String, default: null },
    dataExportUri: { type: String, default: null },
    lifecycleWebhookUri: { type: String, default: null },
    lifecycleEvents: { type: [String], default: [] },
    /** Android signing-cert SHA-1 fingerprints (colon-separated uppercase). */
    androidSha1Fingerprints: {
      type: [String],
      default: [],
    },
  },
  {
    timestamps: true,
  },
);

export const OAuthClient: Model<OAuthClientDocument> =
  (models.OAuthClient as Model<OAuthClientDocument>) ||
  model<OAuthClientDocument>("OAuthClient", oauthClientSchema);
