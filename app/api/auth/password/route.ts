import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { removePassword, setPassword } from "@/lib/account/identities";
import { jsonResponse } from "@/lib/security/headers";
import { securitySession } from "@/lib/security/security-session";
import { passwordSchema } from "@/lib/validation/schemas";

const bodySchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("set"), password: passwordSchema }),
  z.object({ action: z.literal("remove") }),
]);

/**
 * Adds a password to an account without one, or removes it from an account
 * that signs in other ways. Both need a sign-in within the last five
 * minutes; changing an existing password is /api/auth/change-password.
 */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-password", 10, 300);
      await enforceCsrfForCookieAuth(request);
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) {
        throw new AppError(parsed.error.issues[0]?.message ?? "Invalid password request", 400, "invalid_request");
      }
      const { ctx } = await securitySession(true);
      const meta = requestMeta(request);
      return jsonResponse(
        parsed.data.action === "set"
          ? await setPassword(ctx.userId, parsed.data.password, meta)
          : await removePassword(ctx.userId, ctx.session._id.toString(), meta),
      );
    });
  } catch (error) {
    return errorResponse(error);
  }
}
