import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { deleteAccountForSession } from "@/lib/account/delete-account";
import { closeAccount } from "@/lib/account/closure";
import { validateSession } from "@/lib/sessions/session-service";
import { AppError } from "@/lib/api/errors";
import { clearSessionCookie, getSessionTokenFromCookies } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";
import { deleteAccountSchema } from "@/lib/validation/schemas";

/**
 * Closes the signed-in account (web): signed out everywhere at once, deleted for
 * good after a grace period unless undone. Body: { password } or { confirmEmail }.
 */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-delete-account", 5, 600);
      await enforceCsrfForCookieAuth(request);
      const parsed = deleteAccountSchema.safeParse(await readJsonBody(request));
      if (!parsed.success) {
        return jsonResponse(
          { error: "validation_error", message: "Invalid account deletion payload" },
          { status: 400 },
        );
      }
      // Check who's asking, then close with a grace period (lib/account/closure.ts) rather than delete at once.
      const token = await getSessionTokenFromCookies();
      await deleteAccountForSession(token, { ...parsed.data, verifyOnly: true });
      const ctx = await validateSession(token);
      if (!ctx) throw new AppError("Authentication required", 401, "unauthorized");
      const { deleteAfter } = await closeAccount(ctx.userId, requestMeta(request));
      const response = jsonResponse({ ok: true, deleteAfter });
      await clearSessionCookie(response);
      return response;
    });
  } catch (error) {
    return errorResponse(error);
  }
}
