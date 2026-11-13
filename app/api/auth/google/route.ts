import { NextRequest, NextResponse } from "next/server";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceRateLimit } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { securitySession } from "@/lib/security/security-session";
import {
  buildGoogleAuthorizationUrl,
  isGoogleOAuthConfigured,
  newGoogleOAuthSecrets,
  pkceChallengeS256,
} from "@/lib/auth/google";
import { PROVIDER_SIGN_IN_ENABLED, providerSignInOffUrl } from "@/lib/auth/provider-login";
import { safeReturnTo, signOAuthState } from "@/lib/auth/oauth-state";
import { getEnv, isProduction } from "@/lib/config/env";
import { applySecurityHeaders, redirectGet } from "@/lib/security/headers";

const GOOGLE_STATE_COOKIE = "noirly_google_oauth";

export async function GET(request: NextRequest) {
  try {
    await enforceRateLimit(request, "auth-google-start", 20, 60);
    if (!isGoogleOAuthConfigured()) {
      return applySecurityHeaders(
        NextResponse.json(
          { error: "google_not_configured", message: "Google sign-in is not configured" },
          { status: 501 },
        ),
      );
    }

    const env = getEnv();
    const secrets = newGoogleOAuthSecrets();
    // Linking from settings adds a way into the account, so it takes a recent sign-in, like other security changes.
    let linkSessionId: string | undefined;
    // Providers are only linked, never used to sign in.
    if (!PROVIDER_SIGN_IN_ENABLED && request.nextUrl.searchParams.get("intent") !== "link") return redirectGet(providerSignInOffUrl("google", env.APP_URL));
    if (request.nextUrl.searchParams.get("intent") === "link") {
      try {
        const { ctx } = await withDb(() => securitySession(true));
        linkSessionId = ctx.session._id.toString();
      } catch (error) {
        const url = new URL("/account/security", env.APP_URL);
        url.searchParams.set("provider", "google");
        url.searchParams.set("link_error", error instanceof AppError && error.code === "reauth_required" ? "reauth_required" : "unauthorized");
        url.hash = "sign-in-methods";
        return redirectGet(url);
      }
    }
    const returnTo = linkSessionId ? "/account" : safeReturnTo(
      request.nextUrl.searchParams.get("return_to"),
      env.APP_URL,
    );
    const signed = signOAuthState({
      state: secrets.state,
      codeVerifier: secrets.codeVerifier,
      returnTo,
      nonce: secrets.nonce,
      exp: Date.now() + 10 * 60 * 1000,
      linkSessionId,
    });

    const loginHint = request.nextUrl.searchParams.get("login_hint")?.trim() || undefined;
    const authorizeUrl = buildGoogleAuthorizationUrl({
      state: secrets.state,
      nonce: secrets.nonce,
      codeChallenge: pkceChallengeS256(secrets.codeVerifier),
      loginHint,
    });

    const response = applySecurityHeaders(NextResponse.redirect(authorizeUrl));
    response.cookies.set(GOOGLE_STATE_COOKIE, signed, {
      httpOnly: true,
      secure: isProduction(),
      sameSite: "lax",
      path: "/api/auth/google",
      maxAge: 600,
    });
    return response;
  } catch (error) {
    return errorResponse(error);
  }
}
