import { enforceCsrfForCookieAuth, readFormBody } from "@/lib/api/request";
import { NextRequest, NextResponse } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { withDb } from "@/lib/api/with-db";
import { getEnv } from "@/lib/config/env";
import { performLogout } from "@/lib/oidc/logout";
import { clearSessionCookie } from "@/lib/security/cookies";
import { applySecurityHeaders, jsonResponse } from "@/lib/security/headers";

export async function GET(request: NextRequest) {
  const url = new URL('/logout', getEnv().APP_URL);
  url.search = request.nextUrl.search;
  return applySecurityHeaders(NextResponse.redirect(url));
}

export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceCsrfForCookieAuth(request);
      const params = await readFormBody(request);

      const result = await performLogout({
        idTokenHint: params.get("id_token_hint"),
        postLogoutRedirectUri: params.get("post_logout_redirect_uri"),
        clientId: params.get("client_id"),
        state: params.get("state"),
      });

      const response = jsonResponse({ ok: true, redirectTo: result.redirectTo });
      await clearSessionCookie(response);
      return response;
    });
  } catch (error) {
    return errorResponse(error);
  }
}
