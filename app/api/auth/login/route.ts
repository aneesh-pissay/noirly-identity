import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { loginUser } from "@/lib/auth/auth-service";
import { ensureCsrfCookie, setSessionCookie } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";
import { loginSchema } from "@/lib/validation/schemas";

export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-login", 20, 60);
      await enforceCsrfForCookieAuth(request);
      const body = await readJsonBody(request);
      const parsed = loginSchema.safeParse(body);
      if (!parsed.success) {
        return jsonResponse(
          {
            error: "validation_error",
            message: "Invalid login payload",
          },
          { status: 400 },
        );
      }

      const result = await loginUser(parsed.data, {
        ...requestMeta(request),
        userAgent: request.headers.get("user-agent"),
      });

      const response = jsonResponse({ user: result.user });
      await setSessionCookie(response, result.sessionToken);
      await ensureCsrfCookie(response);
      return response;
    });
  } catch (error) {
    return errorResponse(error);
  }
}
