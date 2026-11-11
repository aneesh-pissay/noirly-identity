import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { listSignInMethods, unlinkProvider } from "@/lib/account/identities";
import { PROVIDERS } from "@/lib/account/sign-in-methods";
import { jsonResponse } from "@/lib/security/headers";
import { securitySession } from "@/lib/security/security-session";

/** The signed-in account's ways to sign in. Linking starts at GET /api/auth/google?intent=link. */
export async function GET() {
  try {
    return await withDb(async () => {
      const { ctx } = await securitySession();
      return jsonResponse(await listSignInMethods(ctx.userId));
    });
  } catch (error) {
    return errorResponse(error);
  }
}

const unlinkSchema = z.object({ provider: z.enum(PROVIDERS) });

/** Unlinks a provider, after a sign-in within the last five minutes, unless it's the last way in. */
export async function DELETE(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-identities", 10, 300);
      await enforceCsrfForCookieAuth(request);
      const parsed = unlinkSchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Unknown provider", 400, "invalid_request");
      const { ctx } = await securitySession(true);
      return jsonResponse(await unlinkProvider(ctx.userId, parsed.data.provider, requestMeta(request)));
    });
  } catch (error) {
    return errorResponse(error);
  }
}
