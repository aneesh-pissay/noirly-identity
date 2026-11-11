import { NextRequest } from "next/server";
import { errorResponse, OAuthError } from "@/lib/api/errors";
import { readFormBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { authenticateClient } from "@/lib/oauth/token";
import { hashToken } from "@/lib/security/crypto";
import { jsonResponse } from "@/lib/security/headers";
import { AccessToken } from "@/models/AccessToken";
import { revokeRefreshFamily } from "@/lib/tokens/token-service";

export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      const form = await readFormBody(request);
      const token = form.get("token");
      const tokenTypeHint = form.get("token_type_hint");
      const formClientId = form.get("client_id") || undefined;
      const clientSecret = form.get("client_secret") || undefined;
      const authorization = request.headers.get("authorization");

      if (!token) {
        throw new OAuthError("invalid_request", "token is required");
      }

      // The app says who it is (Basic, or client_id with or without a secret):
      // a confidential one proves it, and only its own tokens are revoked.
      let clientId: string | undefined;
      if (formClientId || authorization?.toLowerCase().startsWith("basic ")) {
        clientId = (await authenticateClient({ clientId: formClientId, clientSecret, authorizationHeader: authorization })).clientId;
      }

      const tokenHash = hashToken(token);
      // Only the app a token was issued to may revoke it (when it says who it is).
      const owner = clientId ? { clientId } : {};
      let revoked = false;

      if (!tokenTypeHint || tokenTypeHint === "access_token") {
        const result = await AccessToken.findOneAndUpdate(
          { tokenHash, revokedAt: null, ...owner },
          { revokedAt: new Date() },
        );
        revoked = !!result;
      }

      if ((!tokenTypeHint || tokenTypeHint === "refresh_token") && !revoked) {
        // A refresh token takes its whole family, and the access tokens from it.
        revoked = await revokeRefreshFamily(token, clientId);
      }

      // RFC 7009: always return 200 even if token is invalid.
      void revoked;
      return jsonResponse({ revoked: true });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
