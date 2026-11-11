import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { addEmailAddress, listEmailAddresses, makePrimaryEmail, removeEmailAddress, resendAddressVerification } from "@/lib/account/emails";
import { securitySession } from "@/lib/security/security-session";
import { jsonResponse } from "@/lib/security/headers";
import { emailSchema } from "@/lib/validation/schemas";

const bodySchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("add"), email: emailSchema }),
  z.object({ action: z.literal("resend"), id: z.string().length(24) }),
  z.object({ action: z.literal("remove"), id: z.string().length(24) }),
  z.object({ action: z.literal("make-primary"), id: z.string().length(24) }),
]);

/** The signed-in account's primary and additional email addresses. */
export async function GET() {
  try {
    return await withDb(async () => {
      const { ctx } = await securitySession();
      return jsonResponse(await listEmailAddresses(ctx.userId));
    });
  } catch (error) {
    return errorResponse(error);
  }
}

/** Add, confirm again, remove, or make primary. Making one primary takes a sign-in within the last five minutes. */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-emails", 20, 300);
      await enforceCsrfForCookieAuth(request);
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Invalid email address request", 400, "invalid_request");
      const body = parsed.data;
      const { ctx } = await securitySession(body.action === "make-primary");
      const meta = requestMeta(request);
      switch (body.action) {
        case "add":
          return jsonResponse(await addEmailAddress(ctx.userId, body.email, meta), { status: 201 });
        case "resend":
          await resendAddressVerification(ctx.userId, body.id);
          return jsonResponse({ ok: true });
        case "remove":
          return jsonResponse(await removeEmailAddress(ctx.userId, body.id, meta));
        case "make-primary":
          return jsonResponse(await makePrimaryEmail(ctx.userId, body.id, meta));
      }
    });
  } catch (error) {
    return errorResponse(error);
  }
}
