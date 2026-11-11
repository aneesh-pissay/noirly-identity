import { NextRequest } from "next/server";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceRateLimit } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { requireAdminUser } from "@/lib/auth/auth-service";
import { verifyStream } from "@/lib/audit/event-log";
import { getSessionTokenFromCookies } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";

/** Checks one stream's hash chain from its first event: `?stream=user:<id>`, `admin` or `system`. */
export async function GET(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "admin-events-verify", 20, 60);
      await requireAdminUser(await getSessionTokenFromCookies());
      const stream = request.nextUrl.searchParams.get("stream");
      if (!stream) throw new AppError("Name a stream to check", 400, "invalid_request");
      return jsonResponse(await verifyStream(stream));
    });
  } catch (error) {
    return errorResponse(error);
  }
}
