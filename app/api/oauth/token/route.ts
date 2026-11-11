import { NextRequest } from "next/server";
import { errorResponse, OAuthError } from "@/lib/api/errors";
import { enforceRateLimit, readFormBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import {
  authenticateClient,
  exchangeAuthorizationCode,
  exchangeRefreshToken,
} from "@/lib/oauth/token";
import { issueClientCredentialsToken } from "@/lib/oauth/client-credentials";
import { jsonResponse } from "@/lib/security/headers";
import { tokenBodySchema } from "@/lib/validation/schemas";

/** RFC 8707 at the token endpoint: one API per access token; repeating `resource` is refused. */
function resourceOf(form: URLSearchParams) {
  const all = form.getAll("resource").filter(Boolean);
  if (all.length > 1) throw new OAuthError("invalid_target", "Ask for one resource per token request");
  return all[0];
}

export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "oauth-token", 60, 60);
      const form = await readFormBody(request);
      const raw = Object.fromEntries(form.entries());
      const parsed = tokenBodySchema.safeParse(raw);
      if (!parsed.success) {
        throw new OAuthError(
          "invalid_request",
          "Invalid token request parameters",
        );
      }

      const authHeader = request.headers.get("authorization");

      if (parsed.data.grant_type === "authorization_code") {
        const tokens = await exchangeAuthorizationCode({
          code: parsed.data.code,
          redirectUri: parsed.data.redirect_uri,
          clientId: parsed.data.client_id,
          clientSecret: parsed.data.client_secret,
          codeVerifier: parsed.data.code_verifier,
          authorizationHeader: authHeader,
          resource: resourceOf(form),
        });
        return jsonResponse(tokens);
      }

      if (parsed.data.grant_type === "client_credentials") {
        // An app acting as itself (lib/oauth/client-credentials.ts).
        const client = await authenticateClient({ clientId: parsed.data.client_id, clientSecret: parsed.data.client_secret, authorizationHeader: authHeader });
        return jsonResponse(await issueClientCredentialsToken({ client, resource: resourceOf(form), scope: parsed.data.scope }));
      }

      const tokens = await exchangeRefreshToken({
        refreshToken: parsed.data.refresh_token,
        clientId: parsed.data.client_id,
        clientSecret: parsed.data.client_secret,
        scope: parsed.data.scope,
        authorizationHeader: authHeader,
        resource: resourceOf(form),
      });
      return jsonResponse(tokens);
    });
  } catch (error) {
    return errorResponse(error);
  }
}
