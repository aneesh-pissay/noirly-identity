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
import { listOAuthClients, registerAppClient } from "@/lib/oauth/client-admin";
import { clientsVisibleTo, ownerEmails, requireAnyClientManager } from "@/lib/oauth/app-owners";
import { getSessionTokenFromCookies } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";
import { registerOAuthClientSchema } from "@/lib/validation/schemas";

export async function GET() {
  try {
    return await withDb(async () => {
      const token = await getSessionTokenFromCookies();
      // Admins see every app; owners only theirs.
      const manager = await requireAnyClientManager(token);
      const clients = await listOAuthClients(clientsVisibleTo(manager));
      return jsonResponse({ clients, owners: await ownerEmails(clients.flatMap((c) => c.ownerIds)) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}

export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "admin-clients-register", 20, 60);
      await enforceCsrfForCookieAuth(request);
      const token = await getSessionTokenFromCookies();
      const admin = await requireAdminUser(token);
      const body = await readJsonBody(request);
      const parsed = registerOAuthClientSchema.safeParse(body);
      if (!parsed.success) {
        return jsonResponse(
          {
            error: "validation_error",
            message: "Invalid OAuth client payload",
            details: parsed.error.flatten(),
          },
          { status: 400 },
        );
      }
      const result = await registerAppClient(parsed.data);
      await recordEvent({
        action: result.created ? "client.registered" : "client.updated",
        stream: ADMIN_STREAM,
        actorId: admin.id,
        clientId: result.client.clientId,
        request: requestMeta(request),
        data: { clientType: result.client.clientType, redirectUris: result.client.redirectUris, requireConsent: result.client.requireConsent },
      });
      return jsonResponse(result, { status: result.created ? 201 : 200 });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
