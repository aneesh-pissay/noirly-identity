import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { confirmRecoveryEmail, recoveryMethods, removeRecoveryEmail, startRecoveryEmail } from "@/lib/account/recovery-methods";
import { jsonResponse } from "@/lib/security/headers";
import { securitySession } from "@/lib/security/security-session";

/** Your recovery methods: a recovery address and the verified phone, never ways to sign in. */
export async function GET() {
  try {
    return await withDb(async () => {
      const { ctx } = await securitySession();
      return jsonResponse(await recoveryMethods(ctx.userId));
    });
  } catch (error) {
    return errorResponse(error);
  }
}

const bodySchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("start-email"), email: z.string().trim().email().max(254) }),
  z.object({ action: z.literal("confirm-email"), code: z.string().trim().max(12) }),
  z.object({ action: z.literal("remove-email") }),
]);

/** Add (a code to the new address, then confirm) or remove the recovery address; after a fresh sign-in. */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "recovery-methods", 20, 300);
      await enforceCsrfForCookieAuth(request);
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Invalid request", 400, "invalid_request");
      const { ctx } = await securitySession(true);
      const meta = requestMeta(request);
      const body = parsed.data;
      if (body.action === "start-email") await startRecoveryEmail(ctx.userId, body.email);
      if (body.action === "confirm-email") await confirmRecoveryEmail(ctx.userId, body.code, meta);
      if (body.action === "remove-email") await removeRecoveryEmail(ctx.userId, meta);
      return jsonResponse(await recoveryMethods(ctx.userId));
    });
  } catch (error) {
    return errorResponse(error);
  }
}
