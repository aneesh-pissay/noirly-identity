import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { requireAdminUser } from "@/lib/auth/auth-service";
import { listSigningKeys, rotateSigningKeys } from "@/lib/oidc/keys";
import { getSessionTokenFromCookies } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";
import { securitySession } from "@/lib/security/security-session";

const bodySchema = z.object({
  action: z.literal("rotate"),
  /** A leaked key: also stop publishing the old one, so what it signed stops verifying. */
  dropOld: z.boolean().optional(),
});

/** Identity's signing keys: which signs, which is next, which are retiring. Never the private halves. */
export async function GET() {
  try {
    return await withDb(async () => {
      await requireAdminUser(await getSessionTokenFromCookies());
      return jsonResponse({ keys: await listSigningKeys() });
    });
  } catch (error) {
    return errorResponse(error);
  }
}

/** Rotates now, skipping the scheduled wait. Needs a fresh sign-in. */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "admin-keys", 5, 300);
      await enforceCsrfForCookieAuth(request);
      const admin = await requireAdminUser(await getSessionTokenFromCookies());
      await securitySession(true);
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Invalid key request", 400, "invalid_request");
      const result = await rotateSigningKeys({ emergency: true, dropOld: parsed.data.dropOld, actorId: admin.id });
      return jsonResponse({ ...result, keys: await listSigningKeys() });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
