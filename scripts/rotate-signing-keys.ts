import { config } from "dotenv";
import { resolve } from "node:path";
import mongoose from "mongoose";
import { resolveMongoDbName } from "../lib/db/uri";
import { listSigningKeys, rotateSigningKeys } from "../lib/oidc/keys";

config({ path: resolve(process.cwd(), ".env.local") });
config({ path: resolve(process.cwd(), ".env") });

/**
 * Signing key rollover (lib/oidc/keys.ts). Run it daily: it publishes the next
 * key ahead of time, switches over when one is due, and removes retired keys
 * once their tokens have expired. Nothing changes when nothing is due.
 *
 *   npm run keys:rotate                      # the schedule
 *   npm run keys:rotate -- --now             # rotate now (skips the wait)
 *   npm run keys:rotate -- --now --drop-old  # a leaked key: also unpublish it at once
 */
async function main() {
  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error("MONGODB_URI is required.");
  const dbName = resolveMongoDbName(uri, "noirly-identity");
  await mongoose.connect(uri, dbName ? { dbName } : undefined);
  const emergency = process.argv.includes("--now");
  const dropOld = process.argv.includes("--drop-old");
  if (dropOld && !emergency) throw new Error("--drop-old only goes with --now");
  const result = await rotateSigningKeys({ emergency, dropOld });
  if (result.created.length) console.log(`Published: ${result.created.join(", ")}`);
  if (result.activated) console.log(`Now signing with ${result.activated}${result.retired.length ? `; retired ${result.retired.join(", ")}` : ""}`);
  if (result.removed.length) console.log(`Removed: ${result.removed.join(", ")}`);
  if (!result.created.length && !result.activated && !result.removed.length) console.log("Nothing due.");
  for (const key of await listSigningKeys()) console.log(`  ${key.state.padEnd(8)} ${key.kid}${key.removeAfter ? ` (until ${key.removeAfter})` : ""}`);
  await mongoose.disconnect();
}

main().catch(async (error) => {
  console.error(error);
  await mongoose.disconnect().catch(() => undefined);
  process.exit(1);
});
