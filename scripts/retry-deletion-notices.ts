import { config } from "dotenv";
import { resolve } from "node:path";
import mongoose from "mongoose";
import { retryPendingDeletionNotices } from "../lib/account/deletion-webhooks";
import { retryPendingMergeNotices } from "../lib/account/merge-webhooks";
import { resolveMongoDbName } from "../lib/db/uri";
import { retryPendingLogoutNotices } from "../lib/oidc/backchannel-logout";
import { sweepExpiredElevations } from "../lib/authz/elevation";
import { sweepClosedAccounts } from "../lib/account/closure";
import { applyRetention } from "../lib/audit/retention";
import { retryDataExports } from "../lib/account/data-export";
import { checkFederationCertificates } from "../lib/federation/certificates";
import { retryLifecycleWebhooks } from "../lib/webhooks/lifecycle";

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
  // Lifecycle webhooks waiting to be retried (lib/webhooks/lifecycle.ts).
  const lifecycle = await retryLifecycleWebhooks();
  if (lifecycle) console.log(`${lifecycle} lifecycle webhook(s) still waiting.`);
  // Federation certificates: pick up rotations, warn before expiry (lib/federation/certificates.ts).
  const certs = await checkFederationCertificates();
  if (certs.expiring || certs.rotated || certs.removed) console.log(`Federation certificates: ${certs.expiring} expiring, ${certs.rotated} added, ${certs.removed} expired removed.`);
  // Data exports still waiting on apps (lib/account/data-export.ts).
  const collecting = await retryDataExports();
  if (collecting) console.log(`${collecting} data export(s) still collecting.`);
  // Events past their retention go, leaving checkpoints (lib/audit/retention.ts).
  const purged = await applyRetention();
  if (purged) console.log(`${purged} event(s) past retention removed.`);
  // Closed accounts whose grace period is over are deleted for good (lib/account/closure.ts).
  const closed = await sweepClosedAccounts();
  if (closed) console.log(`${closed} closed account(s) deleted.`);
  const pending = await retryPendingDeletionNotices();
  console.log(pending === 0 ? "All deletion notices delivered." : `${pending} notice(s) still pending.`);
  // Merge notices wait the same way.
  const merges = await retryPendingMergeNotices();
  console.log(merges === 0 ? "All merge notices delivered." : `${merges} merge notice(s) still pending.`);
  // Temporary access whose time is up: removed and logged (lib/authz/elevation.ts).
  const ended = await sweepExpiredElevations();
  if (ended) console.log(`${ended} temporary access grant(s) ended.`);
  // And back-channel logouts apps didn't take (lib/oidc/backchannel-logout.ts).
  const logouts = await retryPendingLogoutNotices();
  console.log(logouts === 0 ? "All logout notices delivered." : `${logouts} logout notice(s) still pending.`);
  await mongoose.disconnect();
}

main().catch(async (error) => {
  console.error(error);
  await mongoose.disconnect().catch(() => undefined);
  process.exit(1);
});
