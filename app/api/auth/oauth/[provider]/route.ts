import { NextRequest, NextResponse } from "next/server";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceRateLimit } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { newGoogleOAuthSecrets, pkceChallengeS256 } from "@/lib/auth/google";
import { buildAuthorizationUrl, isProviderConfigured, isRedirectProvider } from "@/lib/auth/oauth-providers";
import { PROVIDER_SIGN_IN_ENABLED, providerSignInOffUrl } from "@/lib/auth/provider-login";
import { safeReturnTo, signOAuthState } from "@/lib/auth/oauth-state";
import { getEnv, isProduction } from "@/lib/config/env";
import { applySecurityHeaders, redirectGet } from "@/lib/security/headers";
import { securitySession } from "@/lib/security/security-session";

/**
 * Starts linking Microsoft or GitHub to the signed-in account (`intent=link`,
 * after a recent sign-in); neither ever signs anyone in. The state, PKCE
 * verifier and nonce ride in a signed cookie for this provider's callback.
 */
export async function GET(request: NextRequest, context: { params: Promise<{ provider: string }> }) {
  try {
    const { provider } = await context.params;
    if (!isRedirectProvider(provider)) return applySecurityHeaders(NextResponse.json({ error: "not_found", message: "Unknown sign-in provider" }, { status: 404 }));
    await enforceRateLimit(request, `auth-${provider}-start`, 20, 60);
    if (!isProviderConfigured(provider)) {
      return applySecurityHeaders(NextResponse.json({ error: `${provider}_not_configured`, message: "This sign-in option is not configured" }, { status: 501 }));
    }
    const env = getEnv();
    const secrets = newGoogleOAuthSecrets();
    let linkSessionId: string | undefined;
    // Providers are only linked, never used to sign in.
    if (!PROVIDER_SIGN_IN_ENABLED && request.nextUrl.searchParams.get("intent") !== "link") return redirectGet(providerSignInOffUrl(provider, env.APP_URL));
    if (request.nextUrl.searchParams.get("intent") === "link") {
      try {
        const { ctx } = await withDb(() => securitySession(true));
        linkSessionId = ctx.session._id.toString();
      } catch (error) {
        const url = new URL("/account/security", env.APP_URL);
        url.searchParams.set("provider", provider);
        url.searchParams.set("link_error", error instanceof AppError && error.code === "reauth_required" ? "reauth_required" : "unauthorized");
        url.hash = "sign-in-methods";
        return redirectGet(url);
      }
    }
    const signed = signOAuthState({
      state: secrets.state,
      codeVerifier: secrets.codeVerifier,
      returnTo: linkSessionId ? "/account" : safeReturnTo(request.nextUrl.searchParams.get("return_to"), env.APP_URL),
      nonce: secrets.nonce,
      exp: Date.now() + 10 * 60 * 1000,
      linkSessionId,
    });
    const authorizeUrl = buildAuthorizationUrl(provider, {
      state: secrets.state,
      nonce: secrets.nonce,
      codeChallenge: pkceChallengeS256(secrets.codeVerifier),
      loginHint: request.nextUrl.searchParams.get("login_hint")?.trim() || undefined,
    });
    const response = applySecurityHeaders(NextResponse.redirect(authorizeUrl));
    response.cookies.set(`noirly_${provider}_oauth`, signed, { httpOnly: true, secure: isProduction(), sameSite: "lax", path: `/api/auth/oauth/${provider}`, maxAge: 600 });
    return response;
  } catch (error) {
    return errorResponse(error);
  }
}
