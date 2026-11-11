import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { ADMIN_STREAM } from "@/lib/audit/chain";
import { recordEvent } from "@/lib/audit/event-log";
import { requireAdminUser } from "@/lib/auth/auth-service";
import { saveApiResource } from "@/lib/oauth/resources";
import { getSessionTokenFromCookies } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";
import { ApiResource } from "@/models/ApiResource";

const bodySchema = z.object({
  identifier: z.string().trim().min(1).max(512),
  name: z.string().trim().min(1).max(120),
  scopes: z.array(z.object({ name: z.string().trim().min(1).max(64), description: z.string().trim().max(200).optional() })).max(50).optional(),
  accessTokenTtlSeconds: z.number().int().optional(),
  allowedClientIds: z.array(z.string().trim().min(1).max(64)).max(100).optional(),
  machineGrants: z.array(z.object({ clientId: z.string().trim().min(1).max(64), scopes: z.array(z.string().trim().min(1).max(64)).max(50) })).max(100).optional(),
  status: z.enum(["active", "disabled"]).optional(),
});

const view = (r: { identifier: string; name: string; scopes: Array<{ name: string; description: string }>; accessTokenTtlSeconds: number; allowedClientIds: string[]; machineGrants?: Array<{ clientId: string; scopes: string[] }>; status: string }) => ({
  identifier: r.identifier,
  name: r.name,
  scopes: r.scopes,
  accessTokenTtlSeconds: r.accessTokenTtlSeconds,
  allowedClientIds: r.allowedClientIds,
  machineGrants: r.machineGrants ?? [],
  status: r.status,
});

/** APIs that accept Identity access tokens (RFC 8707 resources). */
export async function GET() {
  try {
    return await withDb(async () => {
      await requireAdminUser(await getSessionTokenFromCookies());
      const resources = await ApiResource.find({}).sort({ name: 1 }).lean();
      return jsonResponse({ resources: resources.map(view) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}

/** Registers an API, or updates the one with this identifier. */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "admin-resources", 20, 60);
      await enforceCsrfForCookieAuth(request);
      const admin = await requireAdminUser(await getSessionTokenFromCookies());
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Invalid resource", 400, "validation_error");
      const saved = await saveApiResource(parsed.data);
      await recordEvent({ action: "resource.saved", stream: ADMIN_STREAM, actorId: admin.id, subjectId: null, request: requestMeta(request), data: view(saved) });
      return jsonResponse({ resource: view(saved) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
