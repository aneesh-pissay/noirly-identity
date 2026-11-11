import { NextRequest } from "next/server";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceRateLimit } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { getCurrentUser } from "@/lib/auth/auth-service";
import { listActivity } from "@/lib/audit/activity-service";
import { getSessionTokenFromCookies } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";

/** The signed-in account's own security activity: `kind` (sign_in, security, account, apps) and `before` (the cursor). */
export async function GET(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-activity", 60, 60);
      const user = await getCurrentUser(await getSessionTokenFromCookies());
      if (!user) throw new AppError("Authentication required", 401, "unauthorized");
      const params = request.nextUrl.searchParams;
      const before = params.get("before");
      return jsonResponse(await listActivity(user.id, { kind: params.get("kind") ?? undefined, before: before ? Number(before) : undefined }));
    });
  } catch (error) {
    return errorResponse(error);
  }
}
