import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { requireAdminUser } from "@/lib/auth/auth-service";
import { reviewClaims, trimScopes } from "@/lib/oauth/claim-review";
import { getSessionTokenFromCookies } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";

/** Admins: each app's allowed scopes against those people actually granted. */
export async function GET() {
  try {
    return await withDb(async () => {
      await requireAdminUser(await getSessionTokenFromCookies());
      return jsonResponse({ apps: await reviewClaims() });
    });
  } catch (error) {
    return errorResponse(error);
  }
}

const bodySchema = z.object({ clientId: z.string().min(1).max(200), remove: z.array(z.string().max(100)).min(1).max(50) });

/** Admins: trim scopes an app doesn't need. */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "admin-claims", 30, 60);
      await enforceCsrfForCookieAuth(request);
      const admin = await requireAdminUser(await getSessionTokenFromCookies());
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Invalid request", 400, "invalid_request");
      return jsonResponse(await trimScopes(parsed.data.clientId, parsed.data.remove, admin.id));
    });
  } catch (error) {
    return errorResponse(error);
  }
}
