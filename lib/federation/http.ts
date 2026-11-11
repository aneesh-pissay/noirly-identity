import type { NextRequest } from "next/server";
import { AppError } from "@/lib/api/errors";
import { stripAuthorizePrompt } from "@/lib/auth/return-to";
import { getEnv, isProduction } from "@/lib/config/env";
import { SSO_COOKIE } from "@/lib/federation/sso";
import { setSessionCookie } from "@/lib/security/cookies";
import { redirectGet } from "@/lib/security/headers";

/** Ends the sign-in: a session cookie and back where they started, or the login page with why not. */
export async function finishResponse(request: NextRequest, run: () => Promise<{ sessionToken: string; returnTo: string }>) {
  const env = getEnv();
  const clear = (response: ReturnType<typeof redirectGet>) => {
    response.cookies.set(SSO_COOKIE, "", { httpOnly: true, secure: isProduction(), sameSite: "lax", path: "/api/sso", maxAge: 0 });
    return response;
  };
  try {
    const { sessionToken, returnTo } = await run();
    const response = redirectGet(new URL(stripAuthorizePrompt(returnTo), env.APP_URL));
    await setSessionCookie(response, sessionToken);
    return clear(response);
  } catch (error) {
    if (!(error instanceof AppError)) throw error;
    const url = new URL("/login", env.APP_URL);
    url.searchParams.set("error", error.message);
    return clear(redirectGet(url));
  }
}
