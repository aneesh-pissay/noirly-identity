import { config } from "dotenv";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import mongoose from "mongoose";
import { resolveMongoDbName } from "../lib/db/uri";
import { createConformanceSetup, removeConformanceSetup } from "../lib/conformance/setup";

config({ path: resolve(process.cwd(), ".env.local") });
config({ path: resolve(process.cwd(), ".env") });

/**
 * Prepares Identity for the OpenID conformance suite (docs/CONFORMANCE.md).
 *
 *   npm run conformance:setup -- --alias=noirly-staging
 *   npm run conformance:setup -- --suite=https://localhost.emobix.co.uk:8443 --alias=local
 *   npm run conformance:setup -- --remove
 *
 * Writes the suite's config (with the client secrets) and the test account to
 * .conformance/, which is git-ignored. Against anything but localhost it needs
 * --confirm, since it adds clients and an account to that Identity.
 */
function arg(name: string) {
  const found = process.argv.find((a) => a.startsWith(`--${name}=`));
  return found ? found.slice(name.length + 3) : undefined;
}

async function main() {
  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error("MONGODB_URI is required.");
  const dbName = resolveMongoDbName(uri, "noirly-identity");
  await mongoose.connect(uri, dbName ? { dbName } : undefined);

  if (process.argv.includes("--remove")) {
    const removed = await removeConformanceSetup();
    console.log(`Removed ${removed.clients} conformance client(s) and ${removed.users} test account(s).`);
    return;
  }

  const issuer = (arg("issuer") ?? process.env.OIDC_ISSUER ?? "").replace(/\/$/, "");
  if (!issuer) throw new Error("Set OIDC_ISSUER or pass --issuer=");
  const local = /^https?:\/\/(localhost|127\.0\.0\.1)(:|\/|$)/.test(issuer);
  if (!local && !process.argv.includes("--confirm")) {
    throw new Error(`This adds two clients and a test account to ${issuer}. Re-run with --confirm if that's intended.`);
  }
  const setup = await createConformanceSetup({
    issuer,
    suiteUrl: arg("suite") ?? "https://www.certification.openid.net",
    alias: arg("alias") ?? "noirly",
  });

  const dir = resolve(process.cwd(), ".conformance");
  mkdirSync(dir, { recursive: true });
  const configPath = resolve(dir, `${setup.suiteConfig.alias}.json`);
  const accountPath = resolve(dir, `${setup.suiteConfig.alias}.account.json`);
  writeFileSync(configPath, `${JSON.stringify(setup.suiteConfig, null, 2)}\n`, { mode: 0o600 });
  writeFileSync(accountPath, `${JSON.stringify(setup.account, null, 2)}\n`, { mode: 0o600 });
  console.log(`Suite config (paste into the suite's JSON tab): ${configPath}`);
  console.log(`Test account to sign in with: ${accountPath}`);
  console.log("Both hold secrets. Remove everything afterwards with: npm run conformance:setup -- --remove");
}

main()
  .then(() => mongoose.disconnect())
  .catch(async (error) => {
    console.error(error instanceof Error ? error.message : error);
    await mongoose.disconnect().catch(() => undefined);
    process.exit(1);
  });
