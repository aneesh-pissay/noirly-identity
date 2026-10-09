import { z } from "zod";
import { isPasswordStrong } from "@/lib/security/password";
import { INITIAL_SCOPES, SUPPORTED_SCOPES } from "@/types";

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
  avatarUrl: z.string().url().nullable().optional(),
  phoneNumber: z.string().trim().min(5).max(30).nullable().optional(),
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

export const authorizeQuerySchema = z.object({
  client_id: z.string().min(1),
  redirect_uri: z.string().url(),
  response_type: z.literal("code"),
  scope: z.string().min(1).default(INITIAL_SCOPES.join(" ")),
  state: z.string().min(1),
  code_challenge: z.string().min(43).max(128).optional(),
  code_challenge_method: z.enum(["S256"]).optional(),
  nonce: z.string().min(1).optional(),
  prompt: z.enum(["none", "login", "consent", "select_account"]).optional(),
  display: z.enum(["page", "popup"]).optional(),
});

export const tokenBodySchema = z.discriminatedUnion("grant_type", [
  z.object({
    grant_type: z.literal("authorization_code"),
    code: z.string().min(1),
    redirect_uri: z.string().url(),
    client_id: z.string().min(1).optional(),
    client_secret: z.string().min(1).optional(),
    code_verifier: z.string().min(43).max(128).optional(),
  }),
  z.object({
    grant_type: z.literal("refresh_token"),
    refresh_token: z.string().min(1),
    client_id: z.string().min(1).optional(),
    client_secret: z.string().min(1).optional(),
    scope: z.string().optional(),
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
    status: z.enum(["active", "disabled"]).optional(),
    requireConsent: z.boolean().optional(),
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
          value.status ||
          value.requireConsent !== undefined ||
          value.androidSha1Fingerprints !== undefined,
      ),
    { message: "No client updates provided" },
  );

export const consentSchema = z.object({
  client_id: z.string().min(1),
  redirect_uri: z.string().url(),
  scope: z.string().min(1),
  state: z.string().min(1),
  code_challenge: z.string().optional(),
  code_challenge_method: z.enum(["S256"]).optional(),
  nonce: z.string().optional(),
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
