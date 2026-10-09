import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { enforceRateLimit, readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { deleteAccountForAccessToken } from "@/lib/account/delete-account";
import { extractBearerToken } from "@/lib/oidc/userinfo";
import { jsonResponse } from "@/lib/security/headers";
import { deleteAccountSchema } from "@/lib/validation/schemas";

/**
 * Deletes the account behind an app's access token (mobile "Delete account").
 * `Authorization: Bearer <access token>`; body { password } or { confirmEmail }.
 * With `verifyOnly: true` it only checks the proof, so the app can confirm the
 * password before deleting its own data, then call again to delete the account.
 */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "mobile-delete-account", 5, 600);
      const parsed = deleteAccountSchema.safeParse(await readJsonBody(request));
      if (!parsed.success) {
        return jsonResponse(
          { error: "validation_error", message: "Invalid account deletion payload" },
          { status: 400 },
        );
      }
      const result = await deleteAccountForAccessToken(extractBearerToken(request), parsed.data);
      return jsonResponse({ ok: true, deleted: result.deleted });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
