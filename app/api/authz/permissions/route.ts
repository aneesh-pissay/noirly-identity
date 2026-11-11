import { NextRequest } from "next/server";
import { errorResponse, OAuthError } from "@/lib/api/errors";
import { enforceRateLimit } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { contextForSession } from "@/lib/authz/delivery";
import { effectivePermissions } from "@/lib/authz/engine";
import { subjectForToken } from "@/lib/authz/token-subject";
import { extractBearerToken } from "@/lib/oidc/userinfo";
import { jsonResponse } from "@/lib/security/headers";

/** Everything the person (or service account) behind this access token may do right now, in its organization. */
export async function GET(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "authz-permissions", 600, 60);
      const token = extractBearerToken(request);
      if (!token) throw new OAuthError("invalid_token", "Bearer token required", 401);
      const { organizationId, subject, sessionId } = await subjectForToken(token);
      const context = subject.type === "user" ? await contextForSession(sessionId) : {};
      return jsonResponse({ org_id: organizationId, permissions: await effectivePermissions(organizationId, subject, context) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
