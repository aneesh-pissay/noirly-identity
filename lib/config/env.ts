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
    /** `clientId=url` pairs: apps told when an account is deleted (lib/account/deletion-webhooks.ts). */
    ACCOUNT_DELETION_WEBHOOKS: z.string().optional(),
    /** Shown on /privacy and /delete-account as the place to send privacy requests. */
    PRIVACY_CONTACT_EMAIL: z.string().email().optional(),
  })
  .superRefine((env, ctx) => {
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
    ACCOUNT_DELETION_WEBHOOKS: process.env.ACCOUNT_DELETION_WEBHOOKS,
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
