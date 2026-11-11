import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { mobileLoginWithGoogle } from "@/lib/mobile/auth";
import { jsonResponse } from "@/lib/security/headers";
import { mobileGoogleSchema } from "@/lib/validation/schemas";

export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "mobile-google", 20, 60);
      const body = await readJsonBody(request);
      const parsed = mobileGoogleSchema.safeParse(body);
      if (!parsed.success) {
        return jsonResponse(
          { error: "validation_error", message: "Invalid Google sign-in payload" },
          { status: 400 },
        );
      }

      const tokens = await mobileLoginWithGoogle(parsed.data, {
        ...requestMeta(request),
        userAgent: request.headers.get("user-agent"),
      });
      return jsonResponse(tokens);
    });
  } catch (error) {
    return errorResponse(error);
  }
}
