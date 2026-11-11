import { generateKeyPairSync, randomBytes } from "node:crypto";
import { MongoMemoryServer } from "mongodb-memory-server";
import { afterAll, beforeAll, beforeEach, vi } from "vitest";

// The real argon2 whenever this machine can load its native binary; otherwise
// (an application control policy blocking it, say) a test-only stand-in.
vi.mock("argon2", async () => {
  try {
    return await vi.importActual<typeof import("argon2")>("argon2");
  } catch {
    console.warn("argon2 couldn't be loaded here; tests use a scrypt stand-in for password hashing.");
    return await import("./support/argon2-fallback");
  }
});
import { resetEnvCache } from "../lib/config/env";
import { disconnectMongo } from "../lib/db/mongodb";
import { resetSigningKeyCache } from "../lib/oidc/keys";
import { resetAlertRuleCache } from "../lib/audit/alert-rules";
import { resetRateLimitStore } from "../lib/security/rate-limit";
import mongoose from "mongoose";

let mongo: MongoMemoryServer;

function escPem(pem: string): string {
  return pem.replace(/\n/g, "\\n");
}

beforeAll(async () => {
  mongo = await MongoMemoryServer.create();
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  (process.env as { NODE_ENV?: string }).NODE_ENV = "test";
  process.env.MONGODB_URI = mongo.getUri();
  process.env.APP_URL = "http://localhost:3000";
  process.env.OIDC_ISSUER = "http://localhost:3000";
  process.env.SESSION_SECRET = randomBytes(32).toString("hex");
  process.env.ENCRYPTION_KEY = randomBytes(32).toString("hex");
  process.env.JWT_PRIVATE_KEY = escPem(privateKey);
  process.env.JWT_PUBLIC_KEY = escPem(publicKey);
  process.env.JWT_KEY_ID = "test-key-1";
  process.env.EMAIL_PROVIDER = "development";
  process.env.AUTH_CODE_TTL_SECONDS = "60";
  process.env.LOGIN_MAX_ATTEMPTS = "3";
  process.env.LOGIN_WINDOW_SECONDS = "900";
  process.env.LOGIN_LOCKOUT_SECONDS = "900";

  resetEnvCache();
  resetSigningKeyCache();
  await mongoose.connect(process.env.MONGODB_URI);
});

beforeEach(async () => {
  resetRateLimitStore();
  // Keys and alert rules live in the database, which is emptied below.
  resetSigningKeyCache();
  resetAlertRuleCache();
  const collections = await mongoose.connection.db?.collections();
  if (collections) {
    for (const collection of collections) {
      await collection.deleteMany({});
    }
  }
});

afterAll(async () => {
  await disconnectMongo();
  await mongoose.disconnect();
  if (mongo) {
    await mongo.stop();
  }
});
