import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { discoverSignIn } from "@/lib/auth/discovery";
import { jsonResponse } from "@/lib/security/headers";
import { emailSchema } from "@/lib/validation/schemas";

const bodySchema = z.object({ email: emailSchema });

/** Email-first sign-in: the ways to offer for an address (see lib/auth/discovery.ts for what it does and doesn't reveal). */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-discover", 20, 300);
      await enforceCsrfForCookieAuth(request);
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Enter a valid email address", 400, "invalid_request");
      return jsonResponse(await discoverSignIn(parsed.data.email));
    });
  } catch (error) {
    return errorResponse(error);
  }
}
