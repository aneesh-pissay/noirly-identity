import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { undoPrimaryChange } from "@/lib/account/emails";
import { clearSessionCookie } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";

const bodySchema = z.object({ token: z.string().min(20).max(128) });

/**
 * Undoes a primary email change from the link sent to the old address. The
 * token is the proof, as with a password reset; there's no session to check,
 * since whoever made the change may hold it. A POST, so a mail scanner
 * opening the link changes nothing.
 */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-email-undo", 10, 300);
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("This link is invalid", 400, "invalid_token");
      const result = await undoPrimaryChange(parsed.data.token, requestMeta(request));
      const response = jsonResponse(result);
      // Every session was just signed out, this browser's too.
      await clearSessionCookie(response);
      return response;
    });
  } catch (error) {
    return errorResponse(error);
  }
}
