import { NextRequest } from "next/server";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceRateLimit } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { startStepUp } from "@/lib/auth/step-up";
import { sanitizeReturnTo } from "@/lib/auth/return-to";
import { getEnv, isProduction } from "@/lib/config/env";
import { getSessionTokenFromCookies } from "@/lib/security/cookies";
import { redirectGet } from "@/lib/security/headers";
import { MFA_COOKIE } from "@/lib/security/mfa";
import { validateSession } from "@/lib/sessions/session-service";

/**
 * An app asked for a stronger sign-in than this session has: sends the
 * person to confirm with their second step, then back where they were going.
 */
export async function GET(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-step-up", 20, 300);
      const env = getEnv();
      const returnTo = sanitizeReturnTo(request.nextUrl.searchParams.get("return_to"), env.APP_URL) ?? "/account";
      const ctx = await validateSession(await getSessionTokenFromCookies());
      if (!ctx) {
        const login = new URL("/login", env.APP_URL);
        login.searchParams.set("return_to", returnTo);
        return redirectGet(login);
      }
      let challenge: string;
      try {
        challenge = await startStepUp(ctx);
      } catch (error) {
        if (!(error instanceof AppError)) throw error;
        const account = new URL("/account/security", env.APP_URL);
        account.hash = "security-title";
        return redirectGet(account);
      }
      const mfa = new URL("/mfa", env.APP_URL);
      mfa.searchParams.set("return_to", returnTo);
      mfa.searchParams.set("step_up", "1");
      const response = redirectGet(mfa);
      response.cookies.set(MFA_COOKIE, challenge, { httpOnly: true, secure: isProduction(), sameSite: "strict", path: "/", maxAge: 300 });
      return response;
    });
  } catch (error) {
    return errorResponse(error);
  }
}
