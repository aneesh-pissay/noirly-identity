import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { removeAvatar, setAvatar } from "@/lib/account/avatar";
import { MAX_AVATAR_BYTES } from "@/lib/account/avatar-image";
import { readLimitedBytes } from "@/lib/security/body";
import { jsonResponse } from "@/lib/security/headers";
import { securitySession } from "@/lib/security/security-session";

/** Uploads a profile photo: the image itself as the body, its type as Content-Type (PNG, JPEG or WebP). */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-avatar", 20, 300);
      await enforceCsrfForCookieAuth(request);
      const { ctx } = await securitySession();
      const bytes = await readLimitedBytes(request, MAX_AVATAR_BYTES);
      return jsonResponse(await setAvatar(ctx.userId, bytes, request.headers.get("content-type"), requestMeta(request)));
    });
  } catch (error) {
    return errorResponse(error);
  }
}

/** Removes the profile photo. */
export async function DELETE(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceCsrfForCookieAuth(request);
      const { ctx } = await securitySession();
      return jsonResponse(await removeAvatar(ctx.userId, requestMeta(request)));
    });
  } catch (error) {
    return errorResponse(error);
  }
}
