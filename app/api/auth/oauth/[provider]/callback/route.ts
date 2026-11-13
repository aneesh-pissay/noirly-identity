import { NextRequest, NextResponse } from "next/server";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceRateLimit, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { linkProvider } from "@/lib/account/identities";
import { PROVIDER_LABEL } from "@/lib/account/sign-in-methods";
import { exchangeCode, isRedirectProvider, type RedirectProvider } from "@/lib/auth/oauth-providers";
import { readOAuthState } from "@/lib/auth/oauth-state";
import { loginWithProviderProfile } from "@/lib/auth/provider-login";
import { stripAuthorizePrompt } from "@/lib/auth/return-to";
import { getEnv, isProduction } from "@/lib/config/env";
import { getSessionTokenFromCookies, setSessionCookie } from "@/lib/security/cookies";
import { safeEqualString } from "@/lib/security/crypto";
import { applySecurityHeaders, redirectGet } from "@/lib/security/headers";
import { mfaRedirect } from "@/lib/security/mfa-redirect";
import { validateSession } from "@/lib/sessions/session-service";

const stateCookie = (provider: RedirectProvider) => `noirly_${provider}_oauth`;

function clearState(response: NextResponse, provider: RedirectProvider) {
  response.cookies.set(stateCookie(provider), "", { httpOnly: true, secure: isProduction(), sameSite: "lax", path: `/api/auth/oauth/${provider}`, maxAge: 0 });
  return response;
}

function loginError(provider: RedirectProvider, message: string) {
  const url = new URL("/login", getEnv().APP_URL);
  url.searchParams.set("error", message);
  return clearState(redirectGet(url), provider);
}

/** Where Microsoft or GitHub send the person back: checks the state, then signs in, or links when settings asked. */
export async function GET(request: NextRequest, context: { params: Promise<{ provider: string }> }) {
  const { provider } = await context.params;
  if (!isRedirectProvider(provider)) return applySecurityHeaders(NextResponse.json({ error: "not_found", message: "Unknown sign-in provider" }, { status: 404 }));
  const label = PROVIDER_LABEL[provider];
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, `auth-${provider}-callback`, 20, 60);
      const env = getEnv();
      const params = request.nextUrl.searchParams;
      if (params.get("error")) return loginError(provider, `${label} sign-in was cancelled`);
      const code = params.get("code");
      const state = params.get("state");
      const payload = readOAuthState(request.cookies.get(stateCookie(provider))?.value);
      if (!code || !state || !payload || !safeEqualString(state, payload.state)) return loginError(provider, `${label} sign-in failed`);

      const profile = await exchangeCode(provider, { code, codeVerifier: payload.codeVerifier, nonce: payload.nonce });
      const meta = requestMeta(request);

      if (payload.linkSessionId) {
        // Linking from settings: the same browser session that asked, still signed in. No new session.
        const back = (outcome: Record<string, string>) => {
          const url = new URL("/account/security", env.APP_URL);
          url.searchParams.set("provider", provider);
          for (const [key, value] of Object.entries(outcome)) url.searchParams.set(key, value);
          url.hash = "sign-in-methods";
          return clearState(redirectGet(url), provider);
        };
        const ctx = await validateSession(await getSessionTokenFromCookies());
        if (!ctx || ctx.session._id.toString() !== payload.linkSessionId) return back({ link_error: "session_changed" });
        try {
          await linkProvider(provider, ctx.userId, profile, meta);
        } catch (error) {
          if (error instanceof AppError) return back({ link_error: error.code });
          throw error;
        }
        return back({ linked: provider });
      }

      const result = await loginWithProviderProfile(provider, profile, meta);
      const response = clearState(redirectGet(new URL(stripAuthorizePrompt(payload.returnTo), env.APP_URL)), provider);
      await setSessionCookie(response, result.sessionToken);
      return response;
    });
  } catch (error) {
    const mfa = mfaRedirect(error, readOAuthState(request.cookies.get(stateCookie(provider))?.value)?.returnTo);
    if (mfa) return mfa;
    // Problems the person can act on go back to the sign-in page, in words.
    if (error instanceof AppError && error.status < 500) return loginError(provider, error.message);
    return errorResponse(error);
  }
}
