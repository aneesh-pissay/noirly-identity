import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { MAGIC_COOKIE, verifyMagicLink } from "@/lib/auth/magic-link";
import { ensureCsrfCookie, setSessionCookie } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";

const bodySchema = z.object({ token: z.string().min(20).max(128) });

/**
 * Signs in with an emailed link, from the page it opens. Needs the secret
 * this browser got when it asked; a second factor, if the account has one,
 * comes next (the usual `mfa_required` answer).
 */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-magic-link-verify", 20, 300);
      await enforceCsrfForCookieAuth(request);
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("This sign-in link is invalid", 400, "invalid_token");
      const result = await verifyMagicLink(parsed.data.token, request.cookies.get(MAGIC_COOKIE)?.value ?? null, requestMeta(request));
      const response = jsonResponse({ user: result.user, redirectTo: result.returnTo });
      await setSessionCookie(response, result.sessionToken);
      await ensureCsrfCookie(response);
      return response;
    });
  } catch (error) {
    return errorResponse(error);
  }
}
