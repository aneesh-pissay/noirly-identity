import { NextResponse } from "next/server";
import { applySecurityHeaders } from "@/lib/security/headers";

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
    return applySecurityHeaders(
      NextResponse.json(
        {
          error: error.error,
          error_description: error.errorDescription,
        },
        { status: error.status },
      ),
    );
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
  if (errorDescription) {
    url.searchParams.set("error_description", errorDescription);
  }
  if (state) {
    url.searchParams.set("state", state);
  }
  return applySecurityHeaders(NextResponse.redirect(url, 303));
}
