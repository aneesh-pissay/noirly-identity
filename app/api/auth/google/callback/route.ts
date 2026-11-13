import { mfaRedirect } from "@/lib/security/mfa-redirect";
import { NextRequest } from "next/server";
import { AppError, errorResponse } from "@/lib/api/errors";
import { linkGoogle } from "@/lib/account/identities";
import { validateSession } from "@/lib/sessions/session-service";
import { enforceRateLimit, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { exchangeGoogleCode, loginWithGoogleProfile } from "@/lib/auth/google";
import { readOAuthState } from "@/lib/auth/oauth-state";
import { stripAuthorizePrompt } from "@/lib/auth/return-to";
import { getEnv, isProduction } from "@/lib/config/env";
import { getSessionTokenFromCookies, setSessionCookie } from "@/lib/security/cookies";
import { redirectGet } from "@/lib/security/headers";
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

      if (payload.linkSessionId) {
        // Linking from settings: the same browser session that asked, still signed in. No new session.
        const back = (outcome: Record<string, string>) => {
          const url = new URL("/account/security", env.APP_URL);
          url.searchParams.set("provider", "google");
          for (const [key, value] of Object.entries(outcome)) url.searchParams.set(key, value);
          url.hash = "sign-in-methods";
          const response = redirectGet(url);
          response.cookies.set(GOOGLE_STATE_COOKIE, "", { httpOnly: true, secure: isProduction(), sameSite: "lax", path: "/api/auth/google", maxAge: 0 });
          return response;
        };
        const ctx = await validateSession(await getSessionTokenFromCookies());
        if (!ctx || ctx.session._id.toString() !== payload.linkSessionId) return back({ link_error: "session_changed" });
        try {
          await linkGoogle(ctx.userId, profile, requestMeta(request));
        } catch (error) {
          // A code, not the message: the page says it in its own words, so a crafted link can't put text there.
          if (error instanceof AppError) return back({ link_error: error.code });
          throw error;
        }
        return back({ linked: "google" });
      }

      const result = await loginWithGoogleProfile(profile, {
        ...requestMeta(request),
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
