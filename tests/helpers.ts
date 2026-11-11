import { createHash } from "node:crypto";
import { generateSecureToken } from "@/lib/security/crypto";
import { hashPassword } from "@/lib/security/password";
import { OAuthClient } from "@/models/OAuthClient";
import { User } from "@/models/User";
import { createSession } from "@/lib/sessions/session-service";

export function pkceChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

export async function createTestUser(overrides?: {
  email?: string;
  password?: string;
  status?: "active" | "disabled" | "pending_verification";
  roles?: Array<"user" | "admin">;
}) {
  const password = overrides?.password ?? "StrongPass1!";
  const status = overrides?.status ?? "active";
  const user = await User.create({
    email: (overrides?.email ?? "user@example.com").toLowerCase(),
    passwordHash: await hashPassword(password),
    firstName: "Test",
    lastName: "User",
    displayName: "Test User",
    emailVerified: status === "active",
    status,
    roles: overrides?.roles ?? ["user"],
    lastLoginAt: new Date(),
  });
  return { user, password };
}

export async function createTestClient(overrides?: {
  clientType?: "public" | "confidential";
  requirePkce?: boolean;
  requireConsent?: boolean;
  allowedScopes?: Array<
    "openid" | "profile" | "email" | "offline_access" | "roles" | "organizations" | "permissions"
  >;
  redirectUris?: string[];
}) {
  const clientSecret = generateSecureToken(24);
  const client = await OAuthClient.create({
    clientId: `client_${generateSecureToken(8)}`,
    clientSecretHash:
      (overrides?.clientType ?? "confidential") === "confidential"
        ? await hashPassword(clientSecret)
        : null,
    name: "Test App",
    description: "Test",
    redirectUris: overrides?.redirectUris ?? [
      "http://localhost:3001/api/auth/callback/noirly",
    ],
    postLogoutRedirectUris: ["http://localhost:3001/"],
    allowedScopes: overrides?.allowedScopes ?? [
      "openid",
      "profile",
      "email",
      "offline_access",
    ],
    clientType: overrides?.clientType ?? "confidential",
    status: "active",
    requirePkce: overrides?.requirePkce ?? true,
    requireConsent: overrides?.requireConsent ?? false,
  });
  return { client, clientSecret };
}

export async function createAuthedSession(userId: string) {
  return createSession({ userId, ipAddress: "127.0.0.1", userAgent: "vitest" });
}
