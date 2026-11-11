import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { ADMIN_STREAM } from "@/lib/audit/chain";
import { recordEvent } from "@/lib/audit/event-log";
import { requireClientManager } from "@/lib/oauth/app-owners";
import { addAppEnvironment } from "@/lib/oauth/client-admin";
import { getSessionTokenFromCookies } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";
import { addEnvironmentSchema, oauthClientIdSchema } from "@/lib/validation/schemas";

/**
 * Adds a development, staging or production environment to an app: its own
 * client_id, secret (shown once) and redirect URIs (lib/oauth/environments.ts).
 */
export async function POST(request: NextRequest, context: { params: Promise<{ clientId: string }> }) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "admin-clients-environments", 20, 60);
      await enforceCsrfForCookieAuth(request);
      const clientId = oauthClientIdSchema.safeParse((await context.params).clientId);
      if (!clientId.success) return jsonResponse({ error: "validation_error", message: "Invalid client_id" }, { status: 400 });
      const { user: admin } = await requireClientManager(await getSessionTokenFromCookies(), clientId.data);
      const parsed = addEnvironmentSchema.safeParse(await readJsonBody(request));
      if (!parsed.success) {
        return jsonResponse({ error: "validation_error", message: "Choose an environment and give its origins or redirect URIs" }, { status: 400 });
      }
      const result = await addAppEnvironment(clientId.data, parsed.data);
      await recordEvent({
        action: "client.registered",
        stream: ADMIN_STREAM,
        actorId: admin.id,
        clientId: result.client.clientId,
        request: requestMeta(request),
        data: { environment: result.client.environment, appKey: result.client.appKey, from: clientId.data, redirectUris: result.client.redirectUris },
      });
      return jsonResponse(result, { status: 201 });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
