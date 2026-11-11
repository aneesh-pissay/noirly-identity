import { NextRequest } from "next/server";
import { errorResponse, OAuthError } from "@/lib/api/errors";
import { enforceRateLimit, readFormBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { authenticateClient } from "@/lib/oauth/token";
import { checkSessionBySid, checkSessionForAccessToken } from "@/lib/oidc/session-check";
import { jsonResponse } from "@/lib/security/headers";

/**
 * The session check: is the Identity session behind this sign-in still going?
 * - `Authorization: Bearer <access_token>`: the session that token came from.
 * - A confidential app's credentials (Basic, or `client_id` + `client_secret`)
 *   with `sid` from its ID token: that session, if it signed in to this app.
 * Answers `{ active: false }`, or `{ active: true, sid, expires_at, auth_time }`.
 */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "oidc-session-check", 600, 60);
      const authorization = request.headers.get("authorization");
      if (authorization?.toLowerCase().startsWith("bearer ")) {
        return jsonResponse(await checkSessionForAccessToken(authorization.slice(7).trim()));
      }
      const form = await readFormBody(request);
      const client = await authenticateClient({
        clientId: form.get("client_id") || undefined,
        clientSecret: form.get("client_secret") || undefined,
        authorizationHeader: authorization,
      });
      // A public app has no secret to prove who's asking; it uses its access token instead.
      if (client.clientType !== "confidential") throw new OAuthError("invalid_client", "Public clients check with their access token", 401);
      const sid = form.get("sid");
      if (!sid || sid.length > 128) throw new OAuthError("invalid_request", "sid is required");
      return jsonResponse(await checkSessionBySid(client.clientId, sid));
    });
  } catch (error) {
    return errorResponse(error);
  }
}
