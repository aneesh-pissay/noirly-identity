import { mfaRedirect } from "@/lib/security/mfa-redirect";
import { NextRequest } from "next/server";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceRateLimit, readFormBody, readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import {
  isGoogleOAuthConfigured,
  loginWithGoogleProfile,
  verifyGoogleIdToken,
} from "@/lib/auth/google";
import { resolveOneTapReturnTo } from "@/lib/auth/one-tap-return";
import { getEnv } from "@/lib/config/env";
import { setSessionCookie } from "@/lib/security/cookies";
import { jsonResponse, redirectGet } from "@/lib/security/headers";
import { getClientIp } from "@/lib/security/rate-limit";

async function credentialFromRequest(request: NextRequest): Promise<{
  credential: string;
  nonce?: string;
  returnTo?: string;
}> {
  const contentType = request.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    const body = await readJsonBody<{
      credential?: string;
      nonce?: string;
      return_to?: string;
    }>(request);
    return {
      credential: String(body.credential ?? ""),
      nonce: body.nonce,
      returnTo: body.return_to,
    };
  }
  const form = await readFormBody(request);
  return {
    credential: form.get("credential") ?? "",
    nonce: form.get("nonce") ?? undefined,
    returnTo: form.get("return_to") ?? undefined,
  };
}

export async function POST(request: NextRequest) {
  let returnTo: string | undefined;
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-google-one-tap", 20, 60);
      if (!isGoogleOAuthConfigured()) {
        return jsonResponse(
          { error: "google_not_configured", message: "Google sign-in is not configured" },
          { status: 501 },
        );
      }

      const parsed = await credentialFromRequest(request);
      returnTo = parsed.returnTo;
      if (!parsed.credential) {
        return jsonResponse(
          { error: "invalid_request", message: "Google credential is required" },
          { status: 400 },
        );
      }

      const cookieName = process.env.NODE_ENV === "production" ? "__Host-noirly_google_nonce" : "noirly_google_nonce";
      const nonce = request.cookies.get(cookieName)?.value;
      if (!nonce || parsed.nonce !== nonce) throw new AppError("Restart Google sign-in", 403, "csrf_failed");
      const profile = await verifyGoogleIdToken({
        credential: parsed.credential,
        nonce: parsed.nonce,
      });
      const result = await loginWithGoogleProfile(profile, {
        ipAddress: getClientIp(request),
        userAgent: request.headers.get("user-agent"),
      });

      const redirectTo = await resolveOneTapReturnTo(parsed.returnTo ?? null);
      const env = getEnv();
      const wantsJson = (request.headers.get("accept") ?? "").includes("application/json");
      if (wantsJson && request.headers.get("content-type")?.includes("application/json")) {
        const response = jsonResponse({ ok: true, redirectTo });
        await setSessionCookie(response, result.sessionToken);
        return response;
      }

      const destination = redirectTo.startsWith("http")
        ? redirectTo
        : new URL(redirectTo, env.APP_URL).toString();
      const response = redirectGet(destination);
      await setSessionCookie(response, result.sessionToken);
      return response;
    });
  } catch (error) {
    if (!(request.headers.get("content-type") ?? "").includes("application/json")) {
      const mfa = mfaRedirect(error, returnTo);
      if (mfa) return mfa;
    }
    const accept = request.headers.get("accept") ?? "";
    const isForm = !(request.headers.get("content-type") ?? "").includes("application/json");
    if (isForm && error instanceof AppError && !accept.includes("application/json")) {
      const env = getEnv();
      const url = new URL("/login", env.APP_URL);
      url.searchParams.set("error", error.message);
      if (returnTo) {
        url.searchParams.set("return_to", returnTo);
        try {
          if (new URL(returnTo, env.APP_URL).searchParams.get("display") === "popup") {
            url.searchParams.set("popup", "1");
          }
        } catch {
          /* ignore */
        }
      }
      return redirectGet(url);
    }
    return errorResponse(error);
  }
}
