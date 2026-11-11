import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { changeUserPassword } from "@/lib/auth/auth-service";
import { getSessionTokenFromCookies } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";
import { changePasswordSchema } from "@/lib/validation/schemas";

export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-change-password", 10, 60);
      await enforceCsrfForCookieAuth(request);
      const token = await getSessionTokenFromCookies();
      const body = await readJsonBody(request);
      const parsed = changePasswordSchema.safeParse(body);
      if (!parsed.success) {
        return jsonResponse(
          {
            error: "validation_error",
            message: "Invalid password change payload",
            details: parsed.error.flatten(),
          },
          { status: 400 },
        );
      }
      await changeUserPassword(token, parsed.data, requestMeta(request));
      return jsonResponse({ ok: true });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
