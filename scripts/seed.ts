import { config } from "dotenv";
import { resolve } from "node:path";
import mongoose from "mongoose";
import { generateSecureToken } from "../lib/security/crypto";
import { hashPassword } from "../lib/security/password";
import { resolveMongoDbName } from "../lib/db/uri";
import { OAuthClient } from "../models/OAuthClient";
import { User } from "../models/User";

config({ path: resolve(process.cwd(), ".env.local") });
config({ path: resolve(process.cwd(), ".env") });

async function upsertConfidentialClient(input: {
  clientId: string;
  name: string;
  description: string;
  redirectUri: string;
  postLogout: string;
  requireConsent: boolean;
}) {
  const clientSecret = generateSecureToken(32);
  await OAuthClient.findOneAndDelete({ clientId: input.clientId });
  await OAuthClient.create({
    clientId: input.clientId,
    clientSecretHash: await hashPassword(clientSecret),
    name: input.name,
    description: input.description,
    redirectUris: [input.redirectUri],
    postLogoutRedirectUris: [input.postLogout],
    allowedScopes: ["openid", "profile", "email", "offline_access", "roles"],
    clientType: "confidential",
    status: "active",
    requirePkce: true,
    requireConsent: input.requireConsent,
  });
  return { clientSecret, ...input };
}

async function main() {
  if (process.env.NODE_ENV !== "development" || process.env.ALLOW_DEVELOPMENT_SEED !== "true") {
    throw new Error("Development seed requires NODE_ENV=development and ALLOW_DEVELOPMENT_SEED=true");
  }
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    throw new Error("MONGODB_URI is required. Run npm run env:generate first.");
  }

  const dbName = resolveMongoDbName(uri, "noirly-identity");
  await mongoose.connect(uri, dbName ? { dbName } : undefined);

  const email = "dev@noirly.test";
  const password = process.env.DEV_SEED_PASSWORD;
  if (!password || password.length < 16) throw new Error("Set a unique DEV_SEED_PASSWORD of at least 16 characters");
  let user = await User.findOne({ email });
  if (!user) {
    user = await User.create({
      email,
      passwordHash: await hashPassword(password),
      firstName: "Dev",
      lastName: "User",
      displayName: "Dev User",
      emailVerified: true,
      status: "active",
      roles: ["user", "admin"],
    });
    console.log("Created test user");
  } else {
    console.log("Test user already exists");
  }

  await upsertConfidentialClient({
    clientId: "noirly-crm",
    name: "NoirlyCRM",
    description: "Development OAuth client for Noirly CRM",
    redirectUri: "http://localhost:3001/api/auth/callback/noirly",
    postLogout: "http://localhost:3001/",
    requireConsent: true,
  });

  await upsertConfidentialClient({
    clientId: "noirly-flow",
    name: "NoirlyFlow",
    description: "Development OAuth client for Noirly Flow",
    redirectUri: "http://localhost:3002/api/auth/callback/noirly",
    postLogout: "http://localhost:3002/",
    requireConsent: false,
  });

  console.log("Development seed complete. Credentials are not logged. Use client:register for client provisioning.");

  await mongoose.disconnect();
}

main().catch(async (error) => {
  console.error(error);
  await mongoose.disconnect().catch(() => undefined);
  process.exit(1);
});
