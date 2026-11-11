import { NextRequest } from "next/server";
import { z } from "zod";
import { errorResponse } from "@/lib/api/errors";
import { enforceRateLimit, readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { verifyEmailCode } from "@/lib/auth/email-tokens";
import { jsonResponse } from "@/lib/security/headers";
import { emailSchema } from "@/lib/validation/schemas";

const bodySchema = z.object({ email: emailSchema, code: z.string().max(16) });

/**
 * Confirms a new account's address with the six-digit code from its
 * verification email, for apps and devices where opening the link is
 * awkward. Then sign in as usual.
 */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-verify-email-code", 20, 300);
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) return jsonResponse({ status: "invalid", message: "Enter your email and the six-digit code" }, { status: 400 });
      const result = await verifyEmailCode(parsed.data.email, parsed.data.code);
      const ok = result.status === "verified" || result.status === "already_verified";
      return jsonResponse(
        { status: ok ? result.status : "invalid", message: ok ? "Your email address has been verified." : "That code isn't right, or it has expired. Check the latest email, or send a new one." },
        { status: ok ? 200 : 400 },
      );
    });
  } catch (error) {
    return errorResponse(error);
  }
}
