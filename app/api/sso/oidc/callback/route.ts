import { NextRequest } from "next/server";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceRateLimit, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { finishResponse } from "@/lib/federation/http";
import { completeFederatedSignIn, finishOidc, readSsoState, SSO_COOKIE } from "@/lib/federation/sso";

/** The organization's OIDC provider sends the browser back here with a code. */
export async function GET(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "sso-callback", 30, 60);
      return finishResponse(request, async () => {
        const state = readSsoState(request.cookies.get(SSO_COOKIE)?.value);
        if (!state) throw new AppError("That sign-in has expired; try again", 400, "sso_state");
        const params = request.nextUrl.searchParams;
        const { idp, claims } = await finishOidc(state, { code: params.get("code"), state: params.get("state"), error: params.get("error") });
        const result = await completeFederatedSignIn(idp, claims, { ...requestMeta(request), userAgent: request.headers.get("user-agent") });
        return { sessionToken: result.sessionToken, returnTo: state.returnTo };
      });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
