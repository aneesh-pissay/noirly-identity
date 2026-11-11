import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { registerUser } from "@/lib/auth/auth-service";
import { setSessionCookie, ensureCsrfCookie } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";
import { registerSchema } from "@/lib/validation/schemas";
import { verifySignupChallenge } from "@/lib/security/signup-protection";

export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-register", 10, 60);
      await enforceCsrfForCookieAuth(request);
      const body = await readJsonBody(request);
      const parsed = registerSchema.safeParse(body);
      if (!parsed.success) {
        return jsonResponse(
          {
            error: "validation_error",
            message: "Invalid registration payload",
            details: parsed.error.flatten(),
          },
          { status: 400 },
        );
      }

      // A browser signing up proves it spent a moment's work first.
      await verifySignupChallenge(parsed.data.challenge, parsed.data.solution);
      const result = await registerUser(parsed.data, {
        ...requestMeta(request),
        userAgent: request.headers.get("user-agent"),
      });

      const response = jsonResponse({ user: result.user }, { status: 201 });
      await setSessionCookie(response, result.sessionToken);
      await ensureCsrfCookie(response);
      return response;
    });
  } catch (error) {
    return errorResponse(error);
  }
}
