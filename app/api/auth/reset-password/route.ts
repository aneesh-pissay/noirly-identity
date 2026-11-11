import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { resetUserPassword } from "@/lib/auth/auth-service";
import { jsonResponse } from "@/lib/security/headers";
import { resetPasswordSchema } from "@/lib/validation/schemas";

export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-reset-password", 10, 60);
      const body = await readJsonBody(request);
      const parsed = resetPasswordSchema.safeParse(body);
      if (!parsed.success) {
        return jsonResponse(
          {
            error: "validation_error",
            message: "Invalid reset payload",
            details: parsed.error.flatten(),
          },
          { status: 400 },
        );
      }
      await resetUserPassword(parsed.data.token, parsed.data.newPassword, requestMeta(request));
      return jsonResponse({ ok: true });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
