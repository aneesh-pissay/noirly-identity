import { NextResponse } from "next/server";
import { AppError } from "@/lib/api/errors";
import { getEnv } from "@/lib/config/env";
import { sanitizeReturnTo, stripAuthorizePrompt } from "@/lib/auth/return-to";
import { applySecurityHeaders } from "@/lib/security/headers";

export function mfaRedirect(error: unknown, returnTo?: string | null) {
  if (!(error instanceof AppError) || error.code !== "mfa_required") return null;
  const env = getEnv();
  const url = new URL("/mfa", env.APP_URL);
  url.searchParams.set("return_to", stripAuthorizePrompt(sanitizeReturnTo(returnTo, env.APP_URL) ?? "/account"));
  const response = applySecurityHeaders(NextResponse.redirect(url, 303));
  response.cookies.set("noirly_mfa_challenge", (error.details as { challenge: string }).challenge, { httpOnly: true, secure: env.NODE_ENV === "production", sameSite: "strict", path: "/", maxAge: 300 });
  return response;
}
