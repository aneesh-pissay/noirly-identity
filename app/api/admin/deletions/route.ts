import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { listDeletionStatus, retryDeletionNow } from "@/lib/account/deletion-status";
import { requireAdminUser } from "@/lib/auth/auth-service";
import { getSessionTokenFromCookies } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";

const states = ["confirmed", "pending", "failed"] as const;

/** Admins: which apps confirmed each account deletion (`?state=`, `?sub=`). */
export async function GET(request: NextRequest) {
  try {
    return await withDb(async () => {
      await requireAdminUser(await getSessionTokenFromCookies());
      const params = request.nextUrl.searchParams;
      const state = params.get("state");
      return jsonResponse({
        deletions: await listDeletionStatus({
          state: states.find((s) => s === state),
          sub: params.get("sub")?.slice(0, 64) || undefined,
        }),
      });
    });
  } catch (error) {
    return errorResponse(error);
  }
}

const bodySchema = z.object({ sub: z.string().min(1).max(64) });

/** Admins: retry one account's deletion notices now. */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "admin-deletions", 30, 60);
      await enforceCsrfForCookieAuth(request);
      const admin = await requireAdminUser(await getSessionTokenFromCookies());
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Invalid request", 400, "invalid_request");
      return jsonResponse(await retryDeletionNow(parsed.data.sub, admin.id));
    });
  } catch (error) {
    return errorResponse(error);
  }
}
