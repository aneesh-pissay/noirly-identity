import { NextRequest, NextResponse } from "next/server";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceRateLimit } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { buildAppleAuthorizationUrl, isAppleConfigured } from "@/lib/auth/apple";
import { newGoogleOAuthSecrets } from "@/lib/auth/google";
import { PROVIDER_SIGN_IN_ENABLED, providerSignInOffUrl } from "@/lib/auth/provider-login";
import { safeReturnTo, signOAuthState } from "@/lib/auth/oauth-state";
import { getEnv, isProduction } from "@/lib/config/env";
import { applySecurityHeaders, redirectGet } from "@/lib/security/headers";
import { securitySession } from "@/lib/security/security-session";

const APPLE_STATE_COOKIE = "noirly_apple_oauth";

/** Starts linking Apple to the signed-in account (`intent=link`, after a recent sign-in). Apple never signs anyone in. */
export async function GET(request: NextRequest) {
  try {
    await enforceRateLimit(request, "auth-apple-start", 20, 60);
    if (!isAppleConfigured()) {
      return applySecurityHeaders(NextResponse.json({ error: "apple_not_configured", message: "Sign in with Apple is not configured" }, { status: 501 }));
    }
    const env = getEnv();
    const secrets = newGoogleOAuthSecrets();
    let linkSessionId: string | undefined;
    // Providers are only linked, never used to sign in.
    if (!PROVIDER_SIGN_IN_ENABLED && request.nextUrl.searchParams.get("intent") !== "link") return redirectGet(providerSignInOffUrl("apple", env.APP_URL));
    if (request.nextUrl.searchParams.get("intent") === "link") {
      try {
        const { ctx } = await withDb(() => securitySession(true));
        linkSessionId = ctx.session._id.toString();
      } catch (error) {
        const url = new URL("/account/security", env.APP_URL);
        url.searchParams.set("provider", "apple");
        url.searchParams.set("link_error", error instanceof AppError && error.code === "reauth_required" ? "reauth_required" : "unauthorized");
        url.hash = "sign-in-methods";
        return redirectGet(url);
      }
    }
    const signed = signOAuthState({
      state: secrets.state,
      // Apple has no PKCE for the web; the client secret authenticates instead.
      codeVerifier: secrets.codeVerifier,
      returnTo: linkSessionId ? "/account" : safeReturnTo(request.nextUrl.searchParams.get("return_to"), env.APP_URL),
      nonce: secrets.nonce,
      exp: Date.now() + 10 * 60 * 1000,
      linkSessionId,
    });
    const response = applySecurityHeaders(NextResponse.redirect(buildAppleAuthorizationUrl({ state: secrets.state, nonce: secrets.nonce })));
    response.cookies.set(APPLE_STATE_COOKIE, signed, { httpOnly: true, secure: isProduction(), sameSite: "lax", path: "/api/auth/apple", maxAge: 600 });
    return response;
  } catch (error) {
    return errorResponse(error);
  }
}
