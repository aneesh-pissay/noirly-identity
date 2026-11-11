import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { undoClosure } from "@/lib/account/closure";
import { jsonResponse } from "@/lib/security/headers";

/** Undoes a closure from the emailed link, within the grace period. */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "close-account-undo", 10, 300);
      await enforceCsrfForCookieAuth(request);
      const body = z.object({ token: z.string().max(200) }).safeParse(await readJsonBody(request));
      if (!body.success) throw new AppError("This link has expired", 400, "invalid_token");
      await undoClosure(body.data.token, requestMeta(request));
      return jsonResponse({ reopened: true });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
