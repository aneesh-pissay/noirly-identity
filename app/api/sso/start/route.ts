import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { enforceRateLimit } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { safeReturnTo } from "@/lib/auth/oauth-state";
import { getEnv, isProduction } from "@/lib/config/env";
import { findProvider, SSO_COOKIE, startSso } from "@/lib/federation/sso";
import { redirectGet } from "@/lib/security/headers";

/** Starts "Sign in with your organization": `?email=` (its domain picks the IdP) or `?idp=`, and `return_to`. */
export async function GET(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "sso-start", 30, 60);
      const env = getEnv();
      const params = request.nextUrl.searchParams;
      const email = params.get("email")?.trim().toLowerCase().slice(0, 254) || null;
      const idp = await findProvider({ idpId: params.get("idp"), email });
      if (!idp) {
        const url = new URL("/login", env.APP_URL);
        url.searchParams.set("error", "Single sign-on isn't set up for that address");
        return redirectGet(url);
      }
      const { url, cookie } = await startSso(idp, safeReturnTo(params.get("return_to"), env.APP_URL), email);
      const response = redirectGet(new URL(url));
      response.cookies.set(SSO_COOKIE, cookie, { httpOnly: true, secure: isProduction(), sameSite: "lax", path: "/api/sso", maxAge: 600 });
      return response;
    });
  } catch (error) {
    return errorResponse(error);
  }
}
