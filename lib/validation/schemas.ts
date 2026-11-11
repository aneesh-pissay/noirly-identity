import { z } from "zod";
import { isPasswordStrong } from "@/lib/security/password";
import { INITIAL_SCOPES, SUPPORTED_SCOPES } from "@/types";
import { canonicalLocale, canonicalTimeZone, CONTRAST, MOTION, TEXT_SIZES } from "@/lib/account/preferences";

export const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .email("Invalid email address")
  .max(320);

export const passwordSchema = z
  .string()
  .min(10, "Password must be at least 10 characters")
  .max(128, "Password must be at most 128 characters")
  .refine(isPasswordStrong, {
    message:
      "Password must include uppercase, lowercase, number, and special character",
  });

export const registerSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
  firstName: z.string().trim().min(1).max(100),
  lastName: z.string().trim().min(1).max(100),
  displayName: z.string().trim().min(1).max(150).optional(),
  phoneNumber: z.string().trim().min(5).max(30).optional().nullable(),
  // The web form's proof of work (lib/security/signup-protection.ts).
  challenge: z.string().max(200).optional(),
  solution: z.string().max(32).optional(),
});

export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1).max(128),
});

export const mobileLoginSchema = loginSchema.extend({
  client_id: z.string().min(1),
  scope: z.string().min(1).optional(),
  nonce: z.string().min(1).max(128).optional(),
});

export const mobileRegisterSchema = registerSchema.extend({
  client_id: z.string().min(1),
  scope: z.string().min(1).optional(),
  nonce: z.string().min(1).max(128).optional(),
});

export const mobileGoogleSchema = z.object({
  client_id: z.string().min(1),
  id_token: z.string().min(20),
  scope: z.string().min(1).optional(),
  nonce: z.string().min(1).max(128).optional(),
});

/** Native Sign in with Apple: Apple's id_token, the raw nonce the app made for Apple, and the name Apple gave on first sign-in. */
export const mobileAppleSchema = z.object({
  client_id: z.string().min(1),
  id_token: z.string().min(20),
  apple_nonce: z.string().min(16).max(128),
  first_name: z.string().trim().max(100).optional(),
  last_name: z.string().trim().max(100).optional(),
  scope: z.string().min(1).optional(),
  nonce: z.string().min(1).max(128).optional(),
});

export const mobileRefreshSchema = z.object({
  client_id: z.string().min(1),
  refresh_token: z.string().min(1),
  scope: z.string().min(1).optional(),
});

export const mobileLogoutSchema = z.object({
  client_id: z.string().min(1),
  refresh_token: z.string().min(1).optional(),
});

export const updateProfileSchema = z.object({
  firstName: z.string().trim().min(1).max(100).optional(),
  lastName: z.string().trim().min(1).max(100).optional(),
  displayName: z.string().trim().min(1).max(150).optional(),
  // Only removed here: a photo is uploaded (/api/auth/avatar), never pointed at somewhere else.
  avatarUrl: z.null().optional(),
  phoneNumber: z.string().trim().min(5).max(30).nullable().optional(),
  // Null goes back to the device's own.
  locale: z.string().max(35).nullable().optional().transform((value, ctx) => {
    if (value == null) return value;
    const tag = canonicalLocale(value);
    if (!tag) ctx.addIssue({ code: "custom", message: "Unknown language" });
    return tag ?? z.NEVER;
  }),
  zoneinfo: z.string().max(64).nullable().optional().transform((value, ctx) => {
    if (value == null) return value;
    const zone = canonicalTimeZone(value);
    if (!zone) ctx.addIssue({ code: "custom", message: "Unknown time zone" });
    return zone ?? z.NEVER;
  }),
  accessibility: z.object({
    motion: z.enum(MOTION),
    contrast: z.enum(CONTRAST),
    textSize: z.enum(TEXT_SIZES),
  }).partial().optional(),
});

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1).max(128),
  newPassword: passwordSchema,
});

/** Proof for deleting an account: the password, or (Google-only accounts) the email typed out. */
export const deleteAccountSchema = z
  .object({
    password: z.string().min(1).max(128).optional(),
    confirmEmail: z.string().trim().max(320).optional(),
    /** Check the proof only, delete nothing (apps verify before removing their own data). */
    verifyOnly: z.boolean().optional(),
  })
  .strict();

export const forgotPasswordSchema = z.object({
  email: emailSchema,
});

export const resendVerificationSchema = z.object({
  email: emailSchema,
});

export const resetPasswordSchema = z.object({
  token: z.string().min(20).max(256),
  newPassword: passwordSchema,
});

export const verifyEmailSchema = z.object({
  token: z.string().min(20).max(256),
});

/** What the authorization endpoint accepts; discovery advertises these same lists. */
export const PROMPT_VALUES = ["none", "login", "consent", "select_account"] as const;
export const DISPLAY_VALUES = ["page", "popup"] as const;
export const CODE_CHALLENGE_METHODS = ["S256"] as const;

export const authorizeQuerySchema = z.object({
  client_id: z.string().min(1),
  redirect_uri: z.string().url(),
  response_type: z.literal("code"),
  scope: z.string().min(1).default(INITIAL_SCOPES.join(" ")),
  // Required, though OIDC only recommends it: a CSRF safeguard for apps without PKCE.
  state: z.string().min(1).max(2048),
  code_challenge: z.string().min(43).max(128).optional(),
  code_challenge_method: z.enum(CODE_CHALLENGE_METHODS).optional(),
  nonce: z.string().min(1).optional(),
  prompt: z.enum(PROMPT_VALUES).optional(),
  display: z.enum(DISPLAY_VALUES).optional(),
  // Step-up (lib/auth/acr.ts): sign-in no older than this many seconds, and the level wanted.
  max_age: z.coerce.number().int().min(0).max(100 * 365 * 86_400).optional(),
  acr_values: z.string().max(512).optional(),
  // Set by Identity itself after prompt=login: the sign-in must be newer than this (ms since epoch).
  noirly_auth_after: z.coerce.number().int().min(0).optional(),
  // RFC 8707: the APIs the app wants tokens for, space-separated (repeats are joined).
  resource: z.string().max(2048).optional(),
  // OpenID Connect claims request (lib/oidc/claims-request.ts), as JSON.
  claims: z.string().max(4096).optional(),
  // Request objects aren't supported; these are only seen to say so (request_not_supported).
  request: z.string().max(16384).optional(),
  request_uri: z.string().max(2048).optional(),
  // A previous ID token: who the app expects to be signed in (lib/oidc/id-token-hint.ts).
  id_token_hint: z.string().max(8192).optional(),
  // Organization context (lib/oauth/org-context.ts): an id or slug, or "select" for the picker.
  organization: z.string().trim().min(1).max(80).optional(),
});

export const tokenBodySchema = z.discriminatedUnion("grant_type", [
  z.object({
    grant_type: z.literal("authorization_code"),
    code: z.string().min(1),
    redirect_uri: z.string().url(),
    client_id: z.string().min(1).optional(),
    client_secret: z.string().min(1).optional(),
    code_verifier: z.string().min(43).max(128).optional(),
    resource: z.string().max(512).optional(),
  }),
  z.object({
    grant_type: z.literal("refresh_token"),
    refresh_token: z.string().min(1),
    client_id: z.string().min(1).optional(),
    client_secret: z.string().min(1).optional(),
    scope: z.string().optional(),
    resource: z.string().max(512).optional(),
  }),
  z.object({
    grant_type: z.literal("client_credentials"),
    client_id: z.string().min(1).optional(),
    client_secret: z.string().min(1).optional(),
    scope: z.string().max(2048).optional(),
    resource: z.string().max(512).optional(),
  }),
]);

export const oauthClientIdSchema = z
  .string()
  .trim()
  .toLowerCase()
  .regex(
    /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/,
    "client_id must be lowercase letters, numbers, and hyphens",
  );

export const oauthCallbackPathSchema = z
  .string()
  .trim()
  .regex(
    /^\/[A-Za-z0-9/_-]*$/,
    "callback path must be an absolute path like /api/auth/callback/noirly",
  )
  .default("/api/auth/callback/noirly");

export const registerOAuthClientSchema = z
  .object({
    clientId: oauthClientIdSchema,
    name: z.string().trim().min(1).max(120),
    clientType: z.enum(["public", "confidential"]).optional().default("confidential"),
    origins: z.array(z.string().trim().min(1)).max(20).optional(),
    redirectUris: z.array(z.string().trim().min(1)).max(20).optional(),
    callbackPath: oauthCallbackPathSchema.optional(),
    requireConsent: z.boolean().optional(),
    /** Android signing certificate SHA-1 fingerprints (with or without colons). */
    androidSha1Fingerprints: z.array(z.string().trim().min(1)).max(20).optional(),
    /** Left out: worked out from the redirect URIs (local only means development). */
    environment: z.enum(["production", "staging", "development"]).optional(),
  })
  .refine(
    (value) =>
      Boolean(value.origins?.length || value.redirectUris?.length),
    {
      message: "Provide at least one app origin or redirect URI",
      path: ["origins"],
    },
  );

export const updateOAuthClientSchema = z
  .object({
    name: z.string().trim().min(1).max(120).optional(),
    clientType: z.enum(["public", "confidential"]).optional(),
    origins: z.array(z.string().trim().min(1)).max(20).optional(),
    redirectUris: z.array(z.string().trim().min(1)).max(20).optional(),
    callbackPath: oauthCallbackPathSchema.optional(),
    rotateSecret: z.boolean().optional(),
    /** With rotateSecret: seconds the old secret keeps working (0 = at once; default a day; at most 7 days). */
    secretOverlapSeconds: z.number().int().min(0).max(7 * 86_400).optional(),
    /** Stop accepting the previous secret now. */
    dropPreviousSecret: z.boolean().optional(),
    /** A leaked secret: also revoke the app's own (client credentials) tokens. */
    revokeMachineTokens: z.boolean().optional(),
    environment: z.enum(["production", "staging", "development"]).optional(),
    /** The app's owners by email (every environment of it); [] for admins only. */
    owners: z.array(z.string().trim().email().max(254)).max(20).optional(),
    /** Who may use it (lib/oauth/access-policy.ts): spaces by slug, people by email. */
    accessPolicy: z
      .object({
        mode: z.enum(["anyone", "spaces", "allowlist"]),
        spaces: z.array(z.string().trim().min(1).max(80)).max(50).optional(),
        emails: z.array(z.string().trim().email().max(254)).max(500).optional(),
      })
      .optional(),
    status: z.enum(["active", "disabled"]).optional(),
    requireConsent: z.boolean().optional(),
    /** Every sign-in to this app needs a second step. */
    requireMfa: z.boolean().optional(),
    /** Logout URIs (lib/oidc/backchannel-logout.ts); "" or null clears. */
    backchannelLogoutUri: z.string().trim().max(2000).nullable().optional(),
    frontchannelLogoutUri: z.string().trim().max(2000).nullable().optional(),
    /** Where Identity asks for one person's data for an export (lib/account/data-export.ts). */
    dataExportUri: z.string().trim().max(2000).nullable().optional(),
    /** Lifecycle webhooks (lib/webhooks/lifecycle.ts). */
    lifecycleWebhookUri: z.string().trim().max(2000).nullable().optional(),
    lifecycleEvents: z.array(z.string().max(40)).max(10).optional(),
    /** When set, replaces the full fingerprint list (use [] to clear). */
    androidSha1Fingerprints: z.array(z.string().trim().min(1)).max(20).optional(),
    /** When true with origins/redirectUris, replace URIs instead of merging. */
    replaceUris: z.boolean().optional(),
  })
  .refine(
    (value) =>
      Boolean(
        value.name ||
          value.clientType ||
          (value.origins && value.origins.length > 0) ||
          (value.redirectUris && value.redirectUris.length > 0) ||
          value.rotateSecret ||
          value.dropPreviousSecret ||
          value.environment ||
          value.owners !== undefined ||
          value.accessPolicy !== undefined ||
          value.revokeMachineTokens ||
          value.status ||
          value.requireConsent !== undefined ||
          value.requireMfa !== undefined ||
          value.backchannelLogoutUri !== undefined ||
          value.frontchannelLogoutUri !== undefined ||
          value.dataExportUri !== undefined ||
          value.lifecycleWebhookUri !== undefined ||
          value.lifecycleEvents !== undefined ||
          value.androidSha1Fingerprints !== undefined,
      ),
    { message: "No client updates provided" },
  );

export const addEnvironmentSchema = z
  .object({
    environment: z.enum(["production", "staging", "development"]),
    origins: z.array(z.string().trim().min(1)).max(20).optional(),
    redirectUris: z.array(z.string().trim().min(1)).max(20).optional(),
    callbackPath: oauthCallbackPathSchema.optional(),
  })
  .refine((value) => Boolean(value.origins?.length || value.redirectUris?.length), { message: "Provide its origins or redirect URIs", path: ["origins"] });

export const consentSchema = z.object({
  client_id: z.string().min(1),
  redirect_uri: z.string().url(),
  scope: z.string().min(1),
  // Required, though OIDC only recommends it: a CSRF safeguard for apps without PKCE.
  state: z.string().min(1).max(2048),
  code_challenge: z.string().optional(),
  code_challenge_method: z.enum(["S256"]).optional(),
  nonce: z.string().optional(),
  resource: z.string().max(2048).optional(),
  organization: z.string().trim().min(1).max(80).optional(),
  decision: z.enum(["approve", "deny"]),
});

export function parseScopes(scope: string): string[] {
  return [...new Set(scope.split(/\s+/).filter(Boolean))];
}

export function validateRequestedScopes(
  requested: string[],
  allowed: string[],
): { ok: true; scopes: string[] } | { ok: false; message: string } {
  for (const scope of requested) {
    if (!(SUPPORTED_SCOPES as readonly string[]).includes(scope)) {
      return { ok: false, message: `Unsupported scope: ${scope}` };
    }
    if (!allowed.includes(scope)) {
      return { ok: false, message: `Scope not allowed for client: ${scope}` };
    }
  }
  if (!requested.includes("openid")) {
    return { ok: false, message: "openid scope is required" };
  }
  return { ok: true, scopes: requested };
}
