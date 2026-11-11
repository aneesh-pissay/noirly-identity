import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { clearSessionCookie } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";
import { securitySession } from "@/lib/security/security-session";
import { cancelUnfreeze, confirmUnfreeze, freezeAccount, freezeByLink, requestUnfreeze } from "@/lib/security/account-lock";

const bodySchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("freeze") }),
  z.object({ action: z.literal("freeze-link"), token: z.string().max(200) }),
  z.object({ action: z.literal("request-unfreeze"), email: z.string().email().max(254) }),
  z.object({ action: z.literal("confirm-unfreeze"), token: z.string().max(200) }),
  z.object({ action: z.literal("cancel-unfreeze"), token: z.string().max(200) }),
]);

/**
 * Freezing and unfreezing your own account (lib/security/account-lock.ts):
 * `freeze` (signed in), `freeze-link` (from a security alert, no sign-in),
 * `request-unfreeze` (by email), `confirm-unfreeze` and `cancel-unfreeze`
 * (from the emailed links).
 */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-freeze", 20, 300);
      await enforceCsrfForCookieAuth(request);
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Invalid request", 400, "invalid_request");
      const meta = requestMeta(request);
      const body = parsed.data;
      if (body.action === "freeze") {
        const { ctx } = await securitySession();
        await freezeAccount(ctx.userId, meta);
        const response = jsonResponse({ frozen: true });
        await clearSessionCookie(response);
        return response;
      }
      if (body.action === "freeze-link") {
        await freezeByLink(body.token, meta);
        const response = jsonResponse({ frozen: true });
        await clearSessionCookie(response);
        return response;
      }
      if (body.action === "request-unfreeze") {
        await requestUnfreeze(body.email);
        return jsonResponse({ sent: true });
      }
      if (body.action === "confirm-unfreeze") return jsonResponse(await confirmUnfreeze(body.token, meta));
      await cancelUnfreeze(body.token, meta);
      return jsonResponse({ cancelled: true });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
