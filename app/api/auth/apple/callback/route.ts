import { NextRequest, NextResponse } from "next/server";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceRateLimit, readFormBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { linkProvider } from "@/lib/account/identities";
import { exchangeAppleCode, loginWithAppleProfile, parseAppleUser } from "@/lib/auth/apple";
import { readOAuthState } from "@/lib/auth/oauth-state";
import { stripAuthorizePrompt } from "@/lib/auth/return-to";
import { getEnv, isProduction } from "@/lib/config/env";
import { getSessionTokenFromCookies, setSessionCookie } from "@/lib/security/cookies";
import { safeEqualString } from "@/lib/security/crypto";
import { redirectGet } from "@/lib/security/headers";
import { mfaRedirect } from "@/lib/security/mfa-redirect";
import { validateSession } from "@/lib/sessions/session-service";

const APPLE_STATE_COOKIE = "noirly_apple_oauth";

/**
 * Apple posts its answer here (form_post). A cross-site POST carries none of
 * this browser's cookies, so it's turned straight into a GET to this same
 * address, which does: the state cookie (and, when linking, the session).
 */
export async function POST(request: NextRequest) {
  try {
    await enforceRateLimit(request, "auth-apple-callback", 20, 60);
    const form = await readFormBody(request);
    const url = new URL("/api/auth/apple/callback", getEnv().APP_URL);
    for (const key of ["code", "state", "user", "error"]) {
      const value = form.get(key);
      if (value) url.searchParams.set(key, value.slice(0, 4096));
    }
    return redirectGet(url);
  } catch (error) {
    return errorResponse(error);
  }
}

export async function GET(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-apple-finish", 20, 60);
      const env = getEnv();
      const clearState = (response: NextResponse) => {
        response.cookies.set(APPLE_STATE_COOKIE, "", { httpOnly: true, secure: isProduction(), sameSite: "lax", path: "/api/auth/apple", maxAge: 0 });
        return response;
      };
      const loginError = (message: string) => {
        const url = new URL("/login", env.APP_URL);
        url.searchParams.set("error", message);
        return clearState(redirectGet(url));
      };

      const params = request.nextUrl.searchParams;
      if (params.get("error")) return loginError("Apple sign-in was cancelled");
      const code = params.get("code");
      const state = params.get("state");
      const payload = readOAuthState(request.cookies.get(APPLE_STATE_COOKIE)?.value);
      if (!code || !state || !payload || !safeEqualString(state, payload.state)) return loginError("Apple sign-in failed");

      const profile = await exchangeAppleCode({ code, nonce: payload.nonce, name: parseAppleUser(params.get("user")) });
      const meta = requestMeta(request);

      if (payload.linkSessionId) {
        // Linking from settings: the same browser session that asked, still signed in. No new session.
        const back = (outcome: Record<string, string>) => {
          const url = new URL("/account/security", env.APP_URL);
          url.searchParams.set("provider", "apple");
          for (const [key, value] of Object.entries(outcome)) url.searchParams.set(key, value);
          url.hash = "sign-in-methods";
          return clearState(redirectGet(url));
        };
        const ctx = await validateSession(await getSessionTokenFromCookies());
        if (!ctx || ctx.session._id.toString() !== payload.linkSessionId) return back({ link_error: "session_changed" });
        try {
          await linkProvider("apple", ctx.userId, profile, meta);
        } catch (error) {
          if (error instanceof AppError) return back({ link_error: error.code });
          throw error;
        }
        return back({ linked: "apple" });
      }

      const result = await loginWithAppleProfile(profile, meta);
      const response = clearState(redirectGet(new URL(stripAuthorizePrompt(payload.returnTo), env.APP_URL)));
      await setSessionCookie(response, result.sessionToken);
      return response;
    });
  } catch (error) {
    const mfa = mfaRedirect(error, readOAuthState(request.cookies.get(APPLE_STATE_COOKIE)?.value)?.returnTo);
    if (mfa) return mfa;
    if (error instanceof AppError && error.code === "linked_elsewhere") {
      const url = new URL("/login", getEnv().APP_URL);
      url.searchParams.set("error", error.message);
      return redirectGet(url);
    }
    return errorResponse(error);
  }
}
