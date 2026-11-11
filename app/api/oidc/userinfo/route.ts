import { NextRequest } from "next/server";
import { errorResponse, OAuthError } from "@/lib/api/errors";
import { readFormBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { buildUserInfo, extractBearerToken } from "@/lib/oidc/userinfo";
import { jsonResponse } from "@/lib/security/headers";

/**
 * UserInfo. The access token comes in the Authorization header, or (POST
 * only) as `access_token` in a form body (RFC 6750 §2.2); never in the query.
 */
async function handle(request: NextRequest, fromBody: boolean) {
  try {
    return await withDb(async () => {
      let token = extractBearerToken(request);
      if (!token && fromBody && (request.headers.get("content-type") ?? "").includes("application/x-www-form-urlencoded")) {
        token = (await readFormBody(request)).get("access_token");
      }
      if (!token) {
        throw new OAuthError("invalid_token", "Bearer token required", 401);
      }
      const claims = await buildUserInfo(token);
      return jsonResponse(claims);
    });
  } catch (error) {
    return errorResponse(error);
  }
}

export async function GET(request: NextRequest) {
  return handle(request, false);
}

export async function POST(request: NextRequest) {
  return handle(request, true);
}
