import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { requireAdminUser } from "@/lib/auth/auth-service";
import { getSessionTokenFromCookies } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";
import { decideRecoveryReview, listRecoveryReviews } from "@/lib/security/recovery";

/** Admin: recoveries started from somewhere risky, waiting for a person to look. */
export async function GET() {
  try {
    return await withDb(async () => {
      await requireAdminUser(await getSessionTokenFromCookies());
      return jsonResponse({ recoveries: await listRecoveryReviews() });
    });
  } catch (error) {
    return errorResponse(error);
  }
}

/** Approve (it can then be finished after its wait) or decline. */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "admin-recoveries", 30, 60);
      await enforceCsrfForCookieAuth(request);
      const admin = await requireAdminUser(await getSessionTokenFromCookies());
      const parsed = z.object({ id: z.string().length(24), approve: z.boolean() }).safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Invalid request", 400, "invalid_request");
      await decideRecoveryReview(admin.id, parsed.data.id, parsed.data.approve, requestMeta(request));
      return jsonResponse({ recoveries: await listRecoveryReviews() });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
