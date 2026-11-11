import type { Accessibility } from "@/lib/account/preferences";

export type UserRole = "user" | "admin";

export type UserStatus = "active" | "disabled" | "pending_verification";

export type ClientType = "public" | "confidential";

export type ClientStatus = "active" | "disabled";

export type OrganizationRole = "owner" | "admin" | "member";

export type OrganizationStatus = "active" | "disabled";

export const SUPPORTED_SCOPES = [
  "openid",
  "profile",
  "email",
  "offline_access",
  "roles",
  "organizations",
  // The person's permissions in the organization a token is scoped to (lib/authz/delivery.ts).
  "permissions",
] as const;

export type Scope = (typeof SUPPORTED_SCOPES)[number];

export const INITIAL_SCOPES = ["openid", "profile", "email"] as const;

export type PublicOAuthClient = {
  clientId: string;
  /** The app it's one environment of, and which (lib/oauth/environments.ts). */
  appKey: string;
  environment: "production" | "staging" | "development";
  /** False for older clients: the environment is only worked out, and its redirect rules don't apply yet. */
  environmentSet: boolean;
  /** Who manages it besides admins (user ids; emails come with listings). */
  ownerIds: string[];
  /** Who may use it: anyone, members of chosen spaces, or an allowlist. */
  accessMode: "anyone" | "spaces" | "allowlist";
  name: string;
  description: string;
  status: ClientStatus;
  clientType: ClientType;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  allowedScopes: string[];
  requirePkce: boolean;
  requireConsent: boolean;
  requireMfa: boolean;
  backchannelLogoutUri: string | null;
  frontchannelLogoutUri: string | null;
  dataExportUri: string | null;
  lifecycleWebhookUri: string | null;
  lifecycleEvents: string[];
  /** Set while the secret before the last rotation still works. */
  previousSecretExpiresAt: string | null;
  previousSecretLastUsedAt: string | null;
  androidSha1Fingerprints: string[];
  createdAt: string;
  updatedAt: string;
};

export type PublicUser = {
  /** The password was found in known data breaches: change it. */
  passwordBreached?: boolean;
  id: string;
  email: string;
  emailVerified: boolean;
  firstName: string;
  lastName: string;
  displayName: string;
  avatarUrl: string | null;
  phoneNumber: string | null;
  phoneVerified: boolean;
  locale: string | null;
  zoneinfo: string | null;
  accessibility: Accessibility;
  hasPassword: boolean;
  status: UserStatus;
  roles: UserRole[];
  createdAt: string;
  updatedAt: string;
  lastLoginAt: string | null;
};
