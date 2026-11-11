import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { getCurrentUser, updateUserProfile } from "@/lib/auth/auth-service";
import {
  ensureCsrfCookie,
  getSessionTokenFromCookies,
} from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";
import { updateProfileSchema } from "@/lib/validation/schemas";

export async function GET() {
  try {
    return await withDb(async () => {
      const token = await getSessionTokenFromCookies();
      const user = await getCurrentUser(token);
      if (!user) {
        return jsonResponse(
          { error: "unauthorized", message: "Authentication required" },
          { status: 401 },
        );
      }
      const response = jsonResponse({ user });
      await ensureCsrfCookie(response);
      return response;
    });
  } catch (error) {
    return errorResponse(error);
  }
}

export async function PATCH(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceCsrfForCookieAuth(request);
      const token = await getSessionTokenFromCookies();
      const body = await readJsonBody(request);
      const parsed = updateProfileSchema.safeParse(body);
      if (!parsed.success) {
        return jsonResponse(
          {
            error: "validation_error",
            message: "Invalid profile payload",
            details: parsed.error.flatten(),
          },
          { status: 400 },
        );
      }
      const user = await updateUserProfile(token, parsed.data, requestMeta(request));
      return jsonResponse({ user });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
