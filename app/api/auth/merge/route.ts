import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { cancelMerge, completeMerge, currentMerge, requestMerge } from "@/lib/account/merge";
import { jsonResponse } from "@/lib/security/headers";
import { securitySession } from "@/lib/security/security-session";
import { emailSchema } from "@/lib/validation/schemas";

const bodySchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("request"), email: emailSchema }),
  z.object({ action: z.literal("complete"), id: z.string().length(24) }),
  z.object({ action: z.literal("cancel"), id: z.string().length(24) }),
]);

/** The signed-in account's open merge request, with what would move once the other account confirms. */
export async function GET() {
  try {
    return await withDb(async () => {
      const { ctx } = await securitySession();
      return jsonResponse({ merge: await currentMerge(ctx.userId) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}

/** Ask to merge another account into this one, complete a confirmed merge, or cancel. Asking and completing need a recent sign-in. */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-merge", 10, 300);
      await enforceCsrfForCookieAuth(request);
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Invalid merge request", 400, "invalid_request");
      const body = parsed.data;
      const { ctx } = await securitySession(body.action !== "cancel");
      const meta = requestMeta(request);
      switch (body.action) {
        case "request":
          await requestMerge(ctx.userId, body.email, meta);
          return jsonResponse({ merge: await currentMerge(ctx.userId) });
        case "complete": {
          const result = await completeMerge(ctx.userId, body.id, meta);
          return jsonResponse({ merged: true, plan: result.plan });
        }
        case "cancel":
          await cancelMerge(ctx.userId, body.id, meta);
          return jsonResponse({ merge: null });
      }
    });
  } catch (error) {
    return errorResponse(error);
  }
}
