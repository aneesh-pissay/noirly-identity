import { mfaRedirect } from "@/lib/security/mfa-redirect";
import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { enforceRateLimit } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { exchangeGoogleCode, loginWithGoogleProfile } from "@/lib/auth/google";
import { readOAuthState } from "@/lib/auth/oauth-state";
import { stripAuthorizePrompt } from "@/lib/auth/return-to";
import { getEnv, isProduction } from "@/lib/config/env";
import { setSessionCookie } from "@/lib/security/cookies";
import { redirectGet } from "@/lib/security/headers";
import { getClientIp } from "@/lib/security/rate-limit";
import { safeEqualString } from "@/lib/security/crypto";

const GOOGLE_STATE_COOKIE = "noirly_google_oauth";

export async function GET(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-google-callback", 20, 60);
      const env = getEnv();
      const loginError = (message: string) => {
        const url = new URL("/login", env.APP_URL);
        url.searchParams.set("error", message);
        const response = redirectGet(url);
        response.cookies.set(GOOGLE_STATE_COOKIE, "", {
          httpOnly: true,
          secure: isProduction(),
          sameSite: "lax",
          path: "/api/auth/google",
          maxAge: 0,
        });
        return response;
      };

      const oauthError = request.nextUrl.searchParams.get("error");
      if (oauthError) {
        return loginError("Google sign-in was cancelled");
      }

      const code = request.nextUrl.searchParams.get("code");
      const state = request.nextUrl.searchParams.get("state");
      const payload = readOAuthState(request.cookies.get(GOOGLE_STATE_COOKIE)?.value);
      if (!code || !state || !payload || !safeEqualString(state, payload.state)) {
        return loginError("Google sign-in failed");
      }

      const profile = await exchangeGoogleCode({
        code,
        codeVerifier: payload.codeVerifier,
      });
      const result = await loginWithGoogleProfile(profile, {
        ipAddress: getClientIp(request),
        userAgent: request.headers.get("user-agent"),
      });

      const redirectTo = new URL(
        stripAuthorizePrompt(payload.returnTo),
        env.APP_URL,
      );
      const response = redirectGet(redirectTo);
      await setSessionCookie(response, result.sessionToken);
      response.cookies.set(GOOGLE_STATE_COOKIE, "", {
        httpOnly: true,
        secure: isProduction(),
        sameSite: "lax",
        path: "/api/auth/google",
        maxAge: 0,
      });
      return response;
    });
  } catch (error) {
    const mfa = mfaRedirect(error, readOAuthState(request.cookies.get(GOOGLE_STATE_COOKIE)?.value)?.returnTo);
    if (mfa) return mfa;
    return errorResponse(error);
  }
}
