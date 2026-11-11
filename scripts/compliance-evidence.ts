import { config } from "dotenv";
import { resolve } from "node:path";
import mongoose from "mongoose";
import { collectEvidence } from "../lib/compliance/evidence";
import { resolveMongoDbName } from "../lib/db/uri";

config({ path: resolve(process.cwd(), ".env.local") });
config({ path: resolve(process.cwd(), ".env") });

/**
 * Prints compliance evidence as JSON (docs/compliance/CONTROLS.md). Exits 1
 * if any check fails, so it can run on a schedule and alert.
 */
async function main() {
  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error("MONGODB_URI is required.");
  const dbName = resolveMongoDbName(uri, "noirly-identity");
  await mongoose.connect(uri, dbName ? { dbName } : undefined);
  const evidence = await collectEvidence();
  console.log(JSON.stringify(evidence, null, 2));
  const failing = Object.entries(evidence).filter(([, v]) => typeof v === "object" && v && "ok" in v && !v.ok).map(([k]) => k);
  if (failing.length) console.error(`Failing checks: ${failing.join(", ")}`);
  await mongoose.disconnect();
  process.exit(failing.length ? 1 : 0);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
