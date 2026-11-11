import { NextRequest } from "next/server";
import { errorResponse, OAuthError } from "@/lib/api/errors";
import { enforceRateLimit, readFormBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { introspectToken } from "@/lib/oauth/introspect";
import { authenticateClient } from "@/lib/oauth/token";
import { jsonResponse } from "@/lib/security/headers";

/**
 * RFC 7662 token introspection. The caller authenticates as a confidential
 * app (Basic, or `client_id` + `client_secret` in the form) and posts `token`
 * (and optionally `token_type_hint`). Answers `{ "active": false }` for
 * anything not live, never saying why.
 */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "oauth-introspect", 1200, 60);
      const form = await readFormBody(request);
      const client = await authenticateClient({
        clientId: form.get("client_id") || undefined,
        clientSecret: form.get("client_secret") || undefined,
        authorizationHeader: request.headers.get("authorization"),
      });
      // Introspection says who a token belongs to: only apps that can prove who they are may ask.
      if (client.clientType !== "confidential") throw new OAuthError("invalid_client", "Introspection needs a confidential client", 401);
      const token = form.get("token");
      if (!token) throw new OAuthError("invalid_request", "token is required");
      return jsonResponse(await introspectToken(token, client.clientId, form.get("token_type_hint")));
    });
  } catch (error) {
    return errorResponse(error);
  }
}
