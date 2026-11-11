import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { MAGIC_COOKIE, verifyMagicCode } from "@/lib/auth/magic-link";
import { ensureCsrfCookie, setSessionCookie } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";
import { emailSchema } from "@/lib/validation/schemas";

const bodySchema = z.object({ email: emailSchema, code: z.string().max(16) });

/** Signs in with the six-digit code from the sign-in email, in the browser that asked for it. */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-magic-code", 20, 300);
      await enforceCsrfForCookieAuth(request);
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Enter the six-digit code from the email", 400, "invalid_code");
      const result = await verifyMagicCode(parsed.data.email, parsed.data.code, request.cookies.get(MAGIC_COOKIE)?.value ?? null, requestMeta(request));
      const response = jsonResponse({ user: result.user, redirectTo: result.returnTo });
      await setSessionCookie(response, result.sessionToken);
      await ensureCsrfCookie(response);
      return response;
    });
  } catch (error) {
    return errorResponse(error);
  }
}
