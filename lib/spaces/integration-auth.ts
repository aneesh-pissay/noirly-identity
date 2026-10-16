import type { NextRequest } from "next/server";
import { AppError } from "@/lib/api/errors";
import { enforceRateLimit } from "@/lib/api/request";
import { authenticateClient } from "@/lib/oauth/token";

/**
 * For /api/integrations/*: the caller is a Noirly app's server, signed in as
 * itself with its OAuth client id and secret (HTTP Basic). Only confidential
 * clients that were granted the `organizations` scope
 * (`npm run client:grant-spaces`) may read or create spaces.
 */
export async function requireSpacesClient(request: NextRequest): Promise<{ clientId: string }> {
  await enforceRateLimit(request, "integrations", 600, 60);
  const client = await authenticateClient({ authorizationHeader: request.headers.get("authorization") });
  if (client.clientType !== "confidential" || !client.allowedScopes.includes("organizations")) {
    throw new AppError("This app isn't allowed to use spaces", 403, "forbidden");
  }
  return { clientId: client.clientId };
}
