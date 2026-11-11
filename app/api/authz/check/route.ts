import { NextRequest } from "next/server";
import { z } from "zod";
import { errorResponse, OAuthError } from "@/lib/api/errors";
import { enforceRateLimit, readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { checkForToken } from "@/lib/authz/delivery";
import { validPermission } from "@/lib/authz/engine";
import { subjectForToken } from "@/lib/authz/token-subject";
import { extractBearerToken } from "@/lib/oidc/userinfo";
import { jsonResponse } from "@/lib/security/headers";

/**
 * The permissions API: may the person (or service account) behind this
 * access token do this, on this resource, now? Default deny, answered live,
 * conditions included. `Authorization: Bearer <access token>`; body
 * `{ permission, resource? }` → `{ allowed }`.
 */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "authz-check", 1200, 60);
      const token = extractBearerToken(request);
      if (!token) throw new OAuthError("invalid_token", "Bearer token required", 401);
      const body = z.object({ permission: z.string().max(100), resource: z.string().max(200).nullable().optional() }).safeParse(await readJsonBody(request));
      if (!body.success || !validPermission(body.data.permission)) throw new OAuthError("invalid_request", 'permission looks like "invoice:read"');
      const { organizationId, subject, sessionId } = await subjectForToken(token);
      return jsonResponse(await checkForToken(organizationId, subject, sessionId, body.data.permission, body.data.resource ?? null));
    });
  } catch (error) {
    return errorResponse(error);
  }
}
