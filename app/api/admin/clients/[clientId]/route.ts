import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import {
  enforceCsrfForCookieAuth,
  enforceRateLimit,
  readJsonBody,
  requestMeta,
} from "@/lib/api/request";
import { recordEvent } from "@/lib/audit/event-log";
import { ADMIN_STREAM } from "@/lib/audit/chain";
import { withDb } from "@/lib/api/with-db";
import { requireAdminUser } from "@/lib/auth/auth-service";
import { deleteAppClient, listOAuthClients, updateAppClient } from "@/lib/oauth/client-admin";
import { requireClientManager, setAppOwners } from "@/lib/oauth/app-owners";
import { setAccessPolicy } from "@/lib/oauth/access-policy";
import { getSessionTokenFromCookies } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";
import {
  oauthClientIdSchema,
  updateOAuthClientSchema,
} from "@/lib/validation/schemas";

export async function PATCH(
  request: NextRequest,
  context: { params: Promise<{ clientId: string }> },
) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "admin-clients-update", 20, 60);
      await enforceCsrfForCookieAuth(request);
      const token = await getSessionTokenFromCookies();

      const { clientId: rawId } = await context.params;
      const clientId = oauthClientIdSchema.safeParse(rawId);
      if (!clientId.success) {
        return jsonResponse(
          { error: "validation_error", message: "Invalid client_id" },
          { status: 400 },
        );
      }
      // Admins, or the app's own owners (lib/oauth/app-owners.ts).
      const { user: admin } = await requireClientManager(token, clientId.data);

      const body = await readJsonBody(request);
      const parsed = updateOAuthClientSchema.safeParse(body);
      if (!parsed.success) {
        return jsonResponse(
          {
            error: "validation_error",
            message: "Invalid OAuth client update",
            details: parsed.error.flatten(),
          },
          { status: 400 },
        );
      }

      const { owners, accessPolicy, ...settings } = parsed.data;
      if (owners !== undefined) await setAppOwners(clientId.data, owners);
      if (accessPolicy !== undefined) await setAccessPolicy(clientId.data, accessPolicy);
      const hasSettings = Object.values(settings).some((value) => value !== undefined);
      const result = hasSettings
        ? await updateAppClient(clientId.data, settings)
        : { client: (await listOAuthClients({ clientId: clientId.data }))[0]!, clientSecret: null };
      // What was asked for, never a secret: a rotation shows as `secretIssued`.
      const { rotateSecret, ...changes } = parsed.data;
      await recordEvent({
        action: "client.updated",
        stream: ADMIN_STREAM,
        actorId: admin.id,
        clientId: clientId.data,
        request: requestMeta(request),
        data: { changes, rotateSecret: Boolean(rotateSecret), secretIssued: Boolean(result.clientSecret) },
      });
      return jsonResponse(result);
    });
  } catch (error) {
    return errorResponse(error);
  }
}

export async function DELETE(
  request: NextRequest,
  context: { params: Promise<{ clientId: string }> },
) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "admin-clients-delete", 20, 60);
      await enforceCsrfForCookieAuth(request);
      const token = await getSessionTokenFromCookies();
      const admin = await requireAdminUser(token);

      const { clientId: rawId } = await context.params;
      const clientId = oauthClientIdSchema.safeParse(rawId);
      if (!clientId.success) {
        return jsonResponse(
          { error: "validation_error", message: "Invalid client_id" },
          { status: 400 },
        );
      }

      await deleteAppClient(clientId.data);
      await recordEvent({ action: "client.deleted", stream: ADMIN_STREAM, actorId: admin.id, clientId: clientId.data, request: requestMeta(request) });
      return jsonResponse({ deleted: true, clientId: clientId.data });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
