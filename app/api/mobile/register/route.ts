import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { mobileRegister } from "@/lib/mobile/auth";
import { jsonResponse } from "@/lib/security/headers";
import { mobileRegisterSchema } from "@/lib/validation/schemas";

export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "mobile-register", 10, 60);
      const body = await readJsonBody(request);
      const parsed = mobileRegisterSchema.safeParse(body);
      if (!parsed.success) {
        return jsonResponse(
          { error: "validation_error", message: "Invalid registration payload" },
          { status: 400 },
        );
      }

      const tokens = await mobileRegister(parsed.data, {
        ...requestMeta(request),
        userAgent: request.headers.get("user-agent"),
      });
      return jsonResponse(tokens);
    });
  } catch (error) {
    return errorResponse(error);
  }
}
