import { NextResponse } from "next/server";
import { applySecurityHeaders } from "@/lib/security/headers";
import { getEnv } from "@/lib/config/env";

export class AppError extends Error {
  constructor(
    message: string,
    public status: number,
    public code: string,
    public details?: unknown,
  ) {
    super(message);
    this.name = "AppError";
  }
}

export class OAuthError extends Error {
  constructor(
    public error: string,
    public errorDescription?: string,
    public status = 400,
  ) {
    super(errorDescription ?? error);
    this.name = "OAuthError";
  }
}

export function errorResponse(error: unknown): NextResponse {
  if (error instanceof AppError) {
    if (error.code === "mfa_required") {
      const details = error.details as { challenge: string; mobile: boolean };
      const response = NextResponse.json({ error: error.code, message: error.message, ...(details.mobile ? { details: { challenge: details.challenge } } : {}) }, { status: 401 });
      if (!details.mobile) response.cookies.set("noirly_mfa_challenge", details.challenge, { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict", path: "/", maxAge: 300 });
      return applySecurityHeaders(response);
    }

    return applySecurityHeaders(
      NextResponse.json(
        {
          error: error.code,
          message: error.message,
          ...(error.details ? { details: error.details } : {}),
        },
        { status: error.status },
      ),
    );
  }

  if (error instanceof OAuthError) {
    const response = NextResponse.json(
      {
        error: error.error,
        error_description: error.errorDescription,
      },
      { status: error.status },
    );
    // Say how to authenticate: RFC 6750 §3 for bearer tokens, RFC 6749 §5.2 for apps.
    if (error.error === "invalid_token" && error.status === 401) {
      response.headers.set("WWW-Authenticate", `Bearer error="invalid_token", error_description="${(error.errorDescription ?? "").replace(/"/g, "'")}"`);
    } else if (error.error === "invalid_client" && error.status === 401) {
      response.headers.set("WWW-Authenticate", 'Basic realm="Noirly Identity"');
    }
    return applySecurityHeaders(response);
  }

  console.error("Unhandled request error");
  return applySecurityHeaders(
    NextResponse.json(
      {
        error: "internal_error",
        message: "An unexpected error occurred",
      },
      { status: 500 },
    ),
  );
}

export function oauthRedirectError(
  redirectUri: string,
  error: string,
  errorDescription?: string,
  state?: string | null,
): NextResponse {
  const url = new URL(redirectUri);
  url.searchParams.set("error", error);
  // RFC 9207: says who answered, so an app talking to several providers can't be mixed up.
  url.searchParams.set("iss", getEnv().OIDC_ISSUER.replace(/\/$/, ""));
  if (errorDescription) {
    url.searchParams.set("error_description", errorDescription);
  }
  if (state) {
    url.searchParams.set("state", state);
  }
  return applySecurityHeaders(NextResponse.redirect(url, 303));
}
