import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { securitySession } from "@/lib/security/security-session";
import { absoluteMaxSeconds, accountSessionPolicy, sessionPolicyFor, setSessionPolicy } from "@/lib/sessions/lifetime";

const bodySchema = z.object({
  idleSeconds: z.number().int().nullable(),
  absoluteSeconds: z.number().int().nullable(),
});

/** How long this account's sessions last, and the longest Identity allows. */
export async function GET() {
  try {
    return await withDb(async () => {
      const { ctx } = await securitySession();
      // Your own choice, and what applies once your organizations' limits are counted.
      return jsonResponse({ policy: await accountSessionPolicy(ctx.userId), effective: await sessionPolicyFor(ctx.userId), defaultAbsoluteSeconds: absoluteMaxSeconds() });
    });
  } catch (error) {
    return errorResponse(error);
  }
}

/**
 * Changes it, for new sessions and every live one. Needs a fresh sign-in:
 * someone holding a stolen session shouldn't be able to make it last.
 */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-session-policy", 10, 300);
      await enforceCsrfForCookieAuth(request);
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Choose how long sessions last", 400, "invalid_request");
      const { ctx } = await securitySession(true);
      const policy = await setSessionPolicy(ctx.userId, parsed.data, String(ctx.session._id), requestMeta(request));
      return jsonResponse({ policy, effective: await sessionPolicyFor(ctx.userId), defaultAbsoluteSeconds: absoluteMaxSeconds() });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
