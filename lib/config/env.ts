import { z } from "zod";

const envSchema = z
  .object({
    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
    MONGODB_URI: z.string().min(1),
    APP_URL: z.string().url(),
    OIDC_ISSUER: z.string().url(),
    SESSION_SECRET: z.string().min(32),
    JWT_PRIVATE_KEY: z.string().min(1),
    JWT_PUBLIC_KEY: z.string().min(1),
    JWT_KEY_ID: z.string().min(1).default("noirly-identity-1"),
    ENCRYPTION_KEY: z.string().min(32),
    SESSION_COOKIE_NAME: z.string().default("noirly_session"),
    CSRF_COOKIE_NAME: z.string().default("noirly_csrf"),
    SESSION_TTL_SECONDS: z.coerce.number().int().positive().default(60 * 60 * 24 * 14),
    ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(3600),
    REFRESH_TOKEN_TTL_SECONDS: z.coerce
      .number()
      .int()
      .positive()
      .default(60 * 60 * 24 * 30),
    AUTH_CODE_TTL_SECONDS: z.coerce.number().int().positive().default(60),
    // Signing key rollover (lib/oidc/keys.ts): how often, and how long a new key is published before it signs.
    SIGNING_KEY_ROTATION_DAYS: z.coerce.number().positive().default(90),
    SIGNING_KEY_PREPUBLISH_HOURS: z.coerce.number().min(2).default(48),
    EMAIL_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(60 * 60 * 24),
    PASSWORD_RESET_TTL_SECONDS: z.coerce.number().int().positive().default(60 * 30),
    RESEND_VERIFICATION_COOLDOWN_SECONDS: z.coerce
      .number()
      .int()
      .positive()
      .default(60),
    LOGIN_MAX_ATTEMPTS: z.coerce.number().int().positive().default(5),
    LOGIN_WINDOW_SECONDS: z.coerce.number().int().positive().default(60 * 15),
    LOGIN_LOCKOUT_SECONDS: z.coerce.number().int().positive().default(60 * 15),
    RATE_LIMIT_WINDOW_SECONDS: z.coerce.number().int().positive().default(60),
    RATE_LIMIT_MAX_REQUESTS: z.coerce.number().int().positive().default(60),
    EMAIL_PROVIDER: z.enum(["development", "smtp"]).default("development"),
    EMAIL_FROM: z.string().optional(),
    SMTP_HOST: z.string().optional(),
    SMTP_PORT: z.coerce.number().int().positive().optional(),
    SMTP_SECURE: z
      .enum(["true", "false"])
      .optional()
      .transform((value) => value === "true"),
    SMTP_USER: z.string().optional(),
    SMTP_PASS: z.string().optional(),
    GOOGLE_CLIENT_ID: z.string().optional(),
    GOOGLE_CLIENT_SECRET: z.string().optional(),
    /** Extra Google OAuth client IDs (iOS/Android) accepted as id_token audiences. */
    GOOGLE_MOBILE_CLIENT_IDS: z.string().optional(),
    /** Sign in with Apple (lib/auth/apple.ts): the Services ID, team, key id and .p8 key. */
    APPLE_CLIENT_ID: z.string().optional(),
    APPLE_TEAM_ID: z.string().optional(),
    APPLE_KEY_ID: z.string().optional(),
    APPLE_PRIVATE_KEY: z.string().optional(),
    /** App bundle ids accepted as audiences of native Apple id_tokens. */
    APPLE_MOBILE_CLIENT_IDS: z.string().optional(),
    /** Sign in with Microsoft (lib/auth/oauth-providers.ts); tenant "common" takes personal and work accounts. */
    MICROSOFT_CLIENT_ID: z.string().optional(),
    MICROSOFT_CLIENT_SECRET: z.string().optional(),
    MICROSOFT_TENANT: z.string().default("common"),
    /** Sign in with GitHub (an OAuth app). */
    GITHUB_CLIENT_ID: z.string().optional(),
    GITHUB_CLIENT_SECRET: z.string().optional(),
    /** Text messages for phone verification (lib/sms/sms-service.ts). Unset: "development" locally, none in production. */
    SMS_PROVIDER: z.enum(["none", "development", "twilio"]).optional(),
    TWILIO_ACCOUNT_SID: z.string().optional(),
    TWILIO_AUTH_TOKEN: z.string().optional(),
    /** A Twilio messaging service (MG…) or sending number (+…). */
    TWILIO_FROM: z.string().optional(),
    /** `clientId=url` pairs: apps told when an account is deleted (lib/account/deletion-webhooks.ts). */
    ACCOUNT_DELETION_WEBHOOKS: z.string().optional(),
    /** `clientId=url` pairs: apps told when one account is merged into another (lib/account/merge-webhooks.ts). */
    ACCOUNT_MERGE_WEBHOOKS: z.string().optional(),
    /** clientId=url pairs told when a space changes (see lib/spaces/space-webhooks.ts). */
    SPACE_WEBHOOKS: z.string().optional(),
    /** Shown on /privacy and /delete-account as the place to send privacy requests. */
    PRIVACY_CONTACT_EMAIL: z.string().email().optional(),
  })
  .superRefine((env, ctx) => {
    if (env.NODE_ENV === "production") {
      for (const key of ["SESSION_SECRET", "ENCRYPTION_KEY"] as const) {
        if (Buffer.byteLength(env[key]) < 32 || new Set(env[key]).size < 10 || /change.?me|replace.?me|example|your.?secret/i.test(env[key])) {
          ctx.addIssue({ code: "custom", path: [key], message: "Use a unique random secret of at least 32 bytes" });
        }
      }
      if (env.SESSION_SECRET === env.ENCRYPTION_KEY) ctx.addIssue({ code: "custom", path: ["ENCRYPTION_KEY"], message: "Encryption and session secrets must be different" });
      for (const key of ["APP_URL", "OIDC_ISSUER"] as const) {
        if (!env[key].startsWith("https://")) ctx.addIssue({ code: "custom", path: [key], message: "HTTPS is required in production" });
      }
      if (env.EMAIL_PROVIDER !== "smtp") ctx.addIssue({ code: "custom", path: ["EMAIL_PROVIDER"], message: "Use SMTP in production" });
    }
    if (env.EMAIL_PROVIDER !== "smtp") {
      return;
    }

    const required: Array<keyof typeof env> = [
      "EMAIL_FROM",
      "SMTP_HOST",
      "SMTP_PORT",
      "SMTP_USER",
      "SMTP_PASS",
    ];

    for (const key of required) {
      if (env[key] === undefined || env[key] === "") {
        ctx.addIssue({
          code: "custom",
          path: [key],
          message: `${key} is required when EMAIL_PROVIDER=smtp`,
        });
      }
    }
  });

export type Env = z.infer<typeof envSchema>;

let cached: Env | null = null;

function normalizePem(value: string): string {
  return value.includes("\\n") ? value.replace(/\\n/g, "\n") : value;
}

export function getEnv(): Env {
  if (cached) {
    return cached;
  }

  const parsed = envSchema.safeParse({
    NODE_ENV: process.env.NODE_ENV,
    MONGODB_URI: process.env.MONGODB_URI,
    APP_URL: process.env.APP_URL,
    OIDC_ISSUER: process.env.OIDC_ISSUER,
    SESSION_SECRET: process.env.SESSION_SECRET,
    JWT_PRIVATE_KEY: process.env.JWT_PRIVATE_KEY,
    JWT_PUBLIC_KEY: process.env.JWT_PUBLIC_KEY,
    JWT_KEY_ID: process.env.JWT_KEY_ID,
    ENCRYPTION_KEY: process.env.ENCRYPTION_KEY,
    SESSION_COOKIE_NAME: process.env.SESSION_COOKIE_NAME,
    CSRF_COOKIE_NAME: process.env.CSRF_COOKIE_NAME,
    SESSION_TTL_SECONDS: process.env.SESSION_TTL_SECONDS,
    ACCESS_TOKEN_TTL_SECONDS: process.env.ACCESS_TOKEN_TTL_SECONDS,
    REFRESH_TOKEN_TTL_SECONDS: process.env.REFRESH_TOKEN_TTL_SECONDS,
    AUTH_CODE_TTL_SECONDS: process.env.AUTH_CODE_TTL_SECONDS,
    SIGNING_KEY_ROTATION_DAYS: process.env.SIGNING_KEY_ROTATION_DAYS,
    SIGNING_KEY_PREPUBLISH_HOURS: process.env.SIGNING_KEY_PREPUBLISH_HOURS,
    EMAIL_TOKEN_TTL_SECONDS: process.env.EMAIL_TOKEN_TTL_SECONDS,
    PASSWORD_RESET_TTL_SECONDS: process.env.PASSWORD_RESET_TTL_SECONDS,
    RESEND_VERIFICATION_COOLDOWN_SECONDS:
      process.env.RESEND_VERIFICATION_COOLDOWN_SECONDS,
    LOGIN_MAX_ATTEMPTS: process.env.LOGIN_MAX_ATTEMPTS,
    LOGIN_WINDOW_SECONDS: process.env.LOGIN_WINDOW_SECONDS,
    LOGIN_LOCKOUT_SECONDS: process.env.LOGIN_LOCKOUT_SECONDS,
    RATE_LIMIT_WINDOW_SECONDS: process.env.RATE_LIMIT_WINDOW_SECONDS,
    RATE_LIMIT_MAX_REQUESTS: process.env.RATE_LIMIT_MAX_REQUESTS,
    EMAIL_PROVIDER: process.env.EMAIL_PROVIDER,
    EMAIL_FROM: process.env.EMAIL_FROM,
    SMTP_HOST: process.env.SMTP_HOST,
    SMTP_PORT: process.env.SMTP_PORT,
    SMTP_SECURE: process.env.SMTP_SECURE,
    SMTP_USER: process.env.SMTP_USER,
    SMTP_PASS: process.env.SMTP_PASS,
    GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET,
    GOOGLE_MOBILE_CLIENT_IDS: process.env.GOOGLE_MOBILE_CLIENT_IDS,
    APPLE_CLIENT_ID: process.env.APPLE_CLIENT_ID,
    APPLE_TEAM_ID: process.env.APPLE_TEAM_ID,
    APPLE_KEY_ID: process.env.APPLE_KEY_ID,
    APPLE_PRIVATE_KEY: process.env.APPLE_PRIVATE_KEY,
    APPLE_MOBILE_CLIENT_IDS: process.env.APPLE_MOBILE_CLIENT_IDS,
    MICROSOFT_CLIENT_ID: process.env.MICROSOFT_CLIENT_ID,
    MICROSOFT_CLIENT_SECRET: process.env.MICROSOFT_CLIENT_SECRET,
    MICROSOFT_TENANT: process.env.MICROSOFT_TENANT || undefined,
    GITHUB_CLIENT_ID: process.env.GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET: process.env.GITHUB_CLIENT_SECRET,
    SMS_PROVIDER: process.env.SMS_PROVIDER || undefined,
    TWILIO_ACCOUNT_SID: process.env.TWILIO_ACCOUNT_SID,
    TWILIO_AUTH_TOKEN: process.env.TWILIO_AUTH_TOKEN,
    TWILIO_FROM: process.env.TWILIO_FROM,
    ACCOUNT_DELETION_WEBHOOKS: process.env.ACCOUNT_DELETION_WEBHOOKS,
    ACCOUNT_MERGE_WEBHOOKS: process.env.ACCOUNT_MERGE_WEBHOOKS,
    SPACE_WEBHOOKS: process.env.SPACE_WEBHOOKS,
    PRIVACY_CONTACT_EMAIL: process.env.PRIVACY_CONTACT_EMAIL || undefined,
  });

  if (!parsed.success) {
    const details = parsed.error.issues
      .map((issue) => `${issue.path.join(".")}: ${issue.message}`)
      .join("; ");
    throw new Error(`Invalid environment configuration: ${details}`);
  }

  cached = {
    ...parsed.data,
    JWT_PRIVATE_KEY: normalizePem(parsed.data.JWT_PRIVATE_KEY),
    JWT_PUBLIC_KEY: normalizePem(parsed.data.JWT_PUBLIC_KEY),
    APPLE_PRIVATE_KEY: parsed.data.APPLE_PRIVATE_KEY ? normalizePem(parsed.data.APPLE_PRIVATE_KEY) : undefined,
    SMTP_SECURE: parsed.data.SMTP_SECURE ?? false,
  };

  return cached;
}

export function resetEnvCache(): void {
  cached = null;
}

export function isProduction(): boolean {
  return getEnv().NODE_ENV === "production";
}
