import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { MAGIC_COOKIE, MAGIC_LINK_MINUTES, requestMagicLink } from "@/lib/auth/magic-link";
import { isProduction } from "@/lib/config/env";
import { jsonResponse } from "@/lib/security/headers";
import { emailSchema } from "@/lib/validation/schemas";

const bodySchema = z.object({ email: emailSchema, return_to: z.string().max(2048).nullable().optional() });

/** Emails a sign-in link that works only in this browser. The answer is the same whether or not the address has an account. */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-magic-link", 10, 300);
      await enforceCsrfForCookieAuth(request);
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Enter a valid email address", 400, "invalid_request");
      const { browserSecret } = await requestMagicLink(parsed.data.email, parsed.data.return_to ?? null, requestMeta(request), request.cookies.get(MAGIC_COOKIE)?.value ?? null);
      const response = jsonResponse({ sent: true, expiresInMinutes: MAGIC_LINK_MINUTES });
      response.cookies.set(MAGIC_COOKIE, browserSecret, {
        httpOnly: true,
        secure: isProduction(),
        sameSite: "strict",
        path: "/api/auth/magic-link",
        maxAge: MAGIC_LINK_MINUTES * 60,
      });
      return response;
    });
  } catch (error) {
    return errorResponse(error);
  }
}
