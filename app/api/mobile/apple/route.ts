import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { mobileLoginWithApple } from "@/lib/mobile/auth";
import { jsonResponse } from "@/lib/security/headers";
import { mobileAppleSchema } from "@/lib/validation/schemas";

/** Native Sign in with Apple: trades Apple's id_token for Noirly tokens, as the Google route does. */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "mobile-apple", 20, 60);
      const parsed = mobileAppleSchema.safeParse(await readJsonBody(request));
      if (!parsed.success) {
        return jsonResponse({ error: "validation_error", message: "Invalid Apple sign-in payload" }, { status: 400 });
      }
      return jsonResponse(await mobileLoginWithApple(parsed.data, requestMeta(request)));
    });
  } catch (error) {
    return errorResponse(error);
  }
}
