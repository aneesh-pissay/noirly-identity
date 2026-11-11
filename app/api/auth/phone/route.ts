import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { confirmPhoneVerification, phoneState, removePhone, startPhoneVerification } from "@/lib/account/phone";
import { jsonResponse } from "@/lib/security/headers";
import { securitySession } from "@/lib/security/security-session";

const bodySchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("start"), phone: z.string().max(32) }),
  z.object({ action: z.literal("confirm"), code: z.string().max(16) }),
  z.object({ action: z.literal("remove") }),
]);

/** The signed-in account's phone number and whether it's verified. */
export async function GET() {
  try {
    return await withDb(async () => {
      const { ctx } = await securitySession();
      return jsonResponse(await phoneState(ctx.userId));
    });
  } catch (error) {
    return errorResponse(error);
  }
}

/** Text a code to a number, confirm it, or remove the number. Sending a code needs a sign-in within the last five minutes. */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-phone", 10, 300);
      await enforceCsrfForCookieAuth(request);
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Invalid phone request", 400, "invalid_request");
      const body = parsed.data;
      const { ctx } = await securitySession(body.action === "start");
      const meta = requestMeta(request);
      switch (body.action) {
        case "start":
          return jsonResponse(await startPhoneVerification(ctx.userId, body.phone, meta));
        case "confirm":
          return jsonResponse(await confirmPhoneVerification(ctx.userId, body.code, meta));
        case "remove":
          return jsonResponse(await removePhone(ctx.userId, meta));
      }
    });
  } catch (error) {
    return errorResponse(error);
  }
}
