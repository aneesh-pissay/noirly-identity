import type { NextRequest } from "next/server";
import { z } from "zod";
import { enforceCsrfForCookieAuth, enforceRateLimit } from "@/lib/api/request";
import { requireAuthContext } from "@/lib/auth/auth-service";
import { assertEmailVerified } from "@/lib/auth/user-policy";
import { getSessionTokenFromCookies } from "@/lib/security/cookies";

export const spaceRoleSchema = z.enum(["owner", "admin", "member"]);

/**
 * The signed-in person behind a Spaces request (web session). Changes also
 * need the CSRF token, like every other cookie-authenticated change here.
 */
export async function spacesUser(request: NextRequest, { change }: { change: boolean }) {
  if (change) {
    await enforceRateLimit(request, "spaces-change", 60, 60);
    await enforceCsrfForCookieAuth(request);
  }
  const auth = await requireAuthContext(await getSessionTokenFromCookies());
  assertEmailVerified(auth.user);
  return { userId: String(auth.user._id) };
}
