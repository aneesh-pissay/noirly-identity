import { NextRequest } from "next/server";
import { AppError, errorResponse } from "@/lib/api/errors";
import { User } from "@/models/User";
import { enforceRateLimit } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { requireAdminUser } from "@/lib/auth/auth-service";
import { listEvents } from "@/lib/audit/event-log";
import { getSessionTokenFromCookies } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";

/**
 * The identity event log, newest first: the admin audit search. Filters:
 * `stream` (user:<id>, org:<id>, admin, system), `action` (exact, or a family
 * such as "auth."), `subjectId` or `email` (the account), `actorId`,
 * `clientId`, `ip`, `from`/`to`, and `before` (the cursor from the last page).
 */
export async function GET(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "admin-events", 60, 60);
      await requireAdminUser(await getSessionTokenFromCookies());
      const params = request.nextUrl.searchParams;
      const limit = Number(params.get("limit") ?? 50);
      const date = (key: string) => {
        const value = params.get(key);
        if (!value) return undefined;
        const parsed = new Date(value);
        if (Number.isNaN(parsed.getTime())) throw new AppError(`${key} isn't a date`, 400, "invalid_request");
        return parsed;
      };
      // An account can be named by email.
      let subjectId = params.get("subjectId") ?? undefined;
      const email = params.get("email");
      if (email && !subjectId) {
        const user = await User.findOne({ email: email.trim().toLowerCase() }).select("_id").lean();
        if (!user) return jsonResponse({ events: [], nextBefore: null });
        subjectId = String(user._id);
      }
      return jsonResponse(await listEvents({
        stream: params.get("stream") ?? undefined,
        action: params.get("action") ?? undefined,
        subjectId,
        actorId: params.get("actorId") ?? undefined,
        clientId: params.get("clientId") ?? undefined,
        ipAddress: params.get("ip") ?? undefined,
        from: date("from"),
        to: date("to"),
        before: params.get("before") ?? undefined,
        limit: Number.isFinite(limit) ? limit : 50,
      }));
    });
  } catch (error) {
    return errorResponse(error);
  }
}
