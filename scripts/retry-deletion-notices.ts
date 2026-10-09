import { config } from "dotenv";
import { resolve } from "node:path";
import mongoose from "mongoose";
import { retryPendingDeletionNotices } from "../lib/account/deletion-webhooks";
import { resolveMongoDbName } from "../lib/db/uri";

config({ path: resolve(process.cwd(), ".env.local") });
config({ path: resolve(process.cwd(), ".env") });

/**
 * Re-sends "account deleted" notices that an app did not accept the first time
 * (it was down, or returned an error). Safe to run on a schedule.
 */
async function main() {
  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error("MONGODB_URI is required.");
  const dbName = resolveMongoDbName(uri, "noirly-identity");
  await mongoose.connect(uri, dbName ? { dbName } : undefined);
  const pending = await retryPendingDeletionNotices();
  console.log(pending === 0 ? "All deletion notices delivered." : `${pending} notice(s) still pending.`);
  await mongoose.disconnect();
}

main().catch(async (error) => {
  console.error(error);
  await mongoose.disconnect().catch(() => undefined);
  process.exit(1);
});
