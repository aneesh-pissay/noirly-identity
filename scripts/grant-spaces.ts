import { config } from "dotenv";
import { resolve } from "node:path";
import mongoose from "mongoose";
import { resolveMongoDbName } from "../lib/db/uri";
import { OAuthClient } from "../models/OAuthClient";

config({ path: resolve(process.cwd(), ".env.local") });
config({ path: resolve(process.cwd(), ".env") });

/**
 * Lets a first-party app use shared spaces: adds the `organizations` scope to
 * its OAuth client, which the /api/integrations/* endpoints require.
 *
 *   npm run client:grant-spaces -- --client-id=noirly-flow
 *   npm run client:grant-spaces -- --client-id=noirly-flow --revoke
 */
function optionalArg(name: string): string | undefined {
  const prefix = `--${name}=`;
  return process.argv.find((value) => value.startsWith(prefix))?.slice(prefix.length);
}

async function main() {
  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error("MONGODB_URI is required.");
  const clientId = optionalArg("client-id")?.trim();
  if (!clientId) throw new Error("Pass --client-id=<app's client id>");
  const revoke = process.argv.includes("--revoke");

  const dbName = resolveMongoDbName(uri, "noirly-identity");
  await mongoose.connect(uri, dbName ? { dbName } : undefined);

  const client = await OAuthClient.findOne({ clientId });
  if (!client) throw new Error(`No OAuth client ${clientId}`);
  if (client.clientType !== "confidential") {
    throw new Error("Only confidential (server-side) clients can use spaces");
  }
  const scopes = new Set(client.allowedScopes);
  if (revoke) scopes.delete("organizations");
  else scopes.add("organizations");
  client.allowedScopes = [...scopes] as typeof client.allowedScopes;
  await client.save();

  console.log(`${revoke ? "Revoked" : "Granted"} spaces for ${clientId}: ${client.allowedScopes.join(", ")}`);
  await mongoose.disconnect();
}

main().catch(async (error) => {
  console.error(error);
  await mongoose.disconnect().catch(() => undefined);
  process.exit(1);
});
