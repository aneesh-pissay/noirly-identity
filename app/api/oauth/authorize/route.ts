import { NextRequest, NextResponse } from "next/server";
import { AppError, errorResponse, oauthRedirectError } from "@/lib/api/errors";
import { readFormBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { getEnv, isProduction } from "@/lib/config/env";
import {
  createAuthorizationCode,
  validateAuthorizeRequest,
} from "@/lib/oauth/authorize";
import { applySecurityHeaders, redirectGet } from "@/lib/security/headers";
import { getSessionTokenFromCookies } from "@/lib/security/cookies";
import { validateSession } from "@/lib/sessions/session-service";
import { authorizeQuerySchema } from "@/lib/validation/schemas";

function buildLoginRedirect(
  requestUrl: string,
  popup: boolean,
  selectAccount: boolean,
): string {
  const env = getEnv();
  const login = new URL("/login", env.APP_URL);
  login.searchParams.set("return_to", requestUrl);
  if (popup) login.searchParams.set("popup", "1");
  if (selectAccount) login.searchParams.set("select_account", "1");
  return login.toString();
}

function buildConsentRedirect(params: URLSearchParams): string {
  const env = getEnv();
  const consent = new URL("/consent", env.APP_URL);
  for (const [key, value] of params.entries()) {
    consent.searchParams.set(key, value);
  }
  return consent.toString();
}

function authorizeUrlFromRequest(request: NextRequest): string {
  const url = request.nextUrl.clone();
  url.searchParams.delete("credential");
  url.searchParams.delete("return_to");
  return url.toString();
}

async function readAuthorizeInput(
  request: NextRequest,
): Promise<Record<string, string>> {
  const fromQuery = Object.fromEntries(request.nextUrl.searchParams.entries());
  if (fromQuery.client_id && fromQuery.response_type) {
    return fromQuery;
  }
  if (request.method !== "POST") {
    return fromQuery;
  }
  const form = await readFormBody(request);
  return Object.fromEntries(form.entries());
}

async function handleAuthorize(request: NextRequest) {
  try {
    return await withDb(async () => {
      const raw = await readAuthorizeInput(request);
      const parsed = authorizeQuerySchema.safeParse(raw);

      if (!parsed.success) {
        return applySecurityHeaders(
          NextResponse.json(
            {
              error: "invalid_request",
              error_description: "Invalid authorization request parameters",
              details: parsed.error.flatten(),
            },
            { status: 400 },
          ),
        );
      }

      const { display, ...params } = parsed.data;

      let validated;
      try {
        validated = await validateAuthorizeRequest(params);
      } catch (error) {
        // Do not redirect on invalid client/redirect — prevent open redirects.
        return errorResponse(error);
      }

      const sessionToken = await getSessionTokenFromCookies();
      const session = await validateSession(sessionToken);
      const forceAccountPicker =
        params.prompt === "login" || params.prompt === "select_account";
      const authorizeUrl = authorizeUrlFromRequest(request);

      if (!session && params.prompt === "none") {
        return oauthRedirectError(
          params.redirect_uri,
          "login_required",
          "Authentication required",
          params.state,
        );
      }

      if (!session || forceAccountPicker) {
        const response = redirectGet(
          buildLoginRedirect(
            authorizeUrl,
            display === "popup",
            forceAccountPicker,
          ),
        );
        response.cookies.set("noirly_oauth_return", authorizeUrl, {
          httpOnly: false,
          sameSite: "lax",
          secure: isProduction(),
          path: "/",
          maxAge: 60 * 60,
        });
        return response;
      }

      const needsConsent =
        validated.client.requireConsent || params.prompt === "consent";

      if (needsConsent) {
        if (params.prompt === "none") {
          return oauthRedirectError(
            params.redirect_uri,
            "consent_required",
            "Consent required",
            params.state,
          );
        }
        return redirectGet(buildConsentRedirect(request.nextUrl.searchParams));
      }

      let code: string;
      try {
        ({ code } = await createAuthorizationCode({
          sessionToken,
          clientId: params.client_id,
          redirectUri: params.redirect_uri,
          scope: validated.scopeString,
          codeChallenge: params.code_challenge,
          codeChallengeMethod: params.code_challenge_method,
          nonce: params.nonce,
        }));
      } catch (error) {
        // Signed up but not verified yet: verify first, then come back here.
        if (error instanceof AppError && error.code === "email_not_verified") {
          const checkEmail = new URL("/check-email", getEnv().APP_URL);
          checkEmail.searchParams.set("return_to", authorizeUrl);
          return redirectGet(checkEmail);
        }
        throw error;
      }

      const redirect = new URL(params.redirect_uri);
      redirect.searchParams.set("code", code);
      redirect.searchParams.set("state", params.state);
      return redirectGet(redirect);
    });
  } catch (error) {
    return errorResponse(error);
  }
}

export async function GET(request: NextRequest) {
  return handleAuthorize(request);
}

export async function POST(request: NextRequest) {
  return handleAuthorize(request);
}
