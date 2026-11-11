import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { listAppAccess, removeAppAccess } from "@/lib/account/app-access";
import { jsonResponse } from "@/lib/security/headers";
import { securitySession } from "@/lib/security/security-session";

/** The apps that have had the signed-in account's details: what each can see, since when, and when it last did. */
export async function GET() {
  try {
    return await withDb(async () => {
      const { ctx } = await securitySession();
      return jsonResponse({ apps: await listAppAccess(ctx.userId) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}

const bodySchema = z.object({ action: z.literal("remove"), clientId: z.string().min(1).max(200) });

/**
 * Removes an app's access. No fresh sign-in needed: taking access away only
 * ever protects the account.
 */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-apps", 20, 300);
      await enforceCsrfForCookieAuth(request);
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Choose an app", 400, "invalid_request");
      const { ctx } = await securitySession();
      const result = await removeAppAccess(ctx.userId, parsed.data.clientId, requestMeta(request));
      return jsonResponse({ ...result, apps: await listAppAccess(ctx.userId) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
