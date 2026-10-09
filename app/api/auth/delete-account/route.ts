import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { deleteAccountForSession } from "@/lib/account/delete-account";
import { clearSessionCookie, getSessionTokenFromCookies } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";
import { deleteAccountSchema } from "@/lib/validation/schemas";

/** Deletes the signed-in account (web). Body: { password } or { confirmEmail }. */
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
      // The web form deletes in one step; verifyOnly is for apps that remove their own data first.
      await deleteAccountForSession(await getSessionTokenFromCookies(), { ...parsed.data, verifyOnly: false });
      const response = jsonResponse({ ok: true });
      await clearSessionCookie(response);
      return response;
    });
  } catch (error) {
    return errorResponse(error);
  }
}
