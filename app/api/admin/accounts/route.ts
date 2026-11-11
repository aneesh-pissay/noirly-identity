import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { requireAdminUser } from "@/lib/auth/auth-service";
import { getSessionTokenFromCookies } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";
import { securitySession } from "@/lib/security/security-session";
import { containAccount, unlockAccount } from "@/lib/security/containment";
import { adminLock } from "@/lib/security/account-lock";
import { User } from "@/models/User";

const bodySchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("contain"), email: z.string().email().optional(), userId: z.string().length(24).optional(), reason: z.string().max(300) }),
  z.object({ action: z.literal("unlock"), email: z.string().email().optional(), userId: z.string().length(24).optional() }),
  z.object({ action: z.literal("lock"), email: z.string().email().optional(), userId: z.string().length(24).optional(), reason: z.string().max(300) }),
]);

/**
 * Account takeover containment (admins, after a fresh sign-in): `contain`
 * locks the account, signs it out everywhere, revokes its app tokens and
 * forces a password reset; `unlock` reopens it and emails a reset link.
 */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "admin-accounts", 20, 60);
      await enforceCsrfForCookieAuth(request);
      const admin = await requireAdminUser(await getSessionTokenFromCookies());
      await securitySession(true);
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success || (!parsed.data.email && !parsed.data.userId)) throw new AppError("Name the account by email or id", 400, "invalid_request");
      const body = parsed.data;
      const target = { email: body.email, userId: body.userId };
      if (body.action === "contain") return jsonResponse(await containAccount(admin.id, target, body.reason, requestMeta(request)));
      if (body.action === "lock") {
        const user = body.userId ? { _id: body.userId } : await User.findOne({ email: (body.email ?? "").trim().toLowerCase() }).select("_id").lean();
        if (!user) throw new AppError("No such account", 404, "not_found");
        await adminLock(admin.id, String(user._id), body.reason, requestMeta(request));
        return jsonResponse({ ok: true });
      }
      await unlockAccount(admin.id, target, requestMeta(request));
      return jsonResponse({ ok: true });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
