import { NextRequest } from "next/server";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceRateLimit, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { getEnv } from "@/lib/config/env";
import { finishResponse } from "@/lib/federation/http";
import { completeFederatedSignIn, finishSaml, parkSamlResponse, readSsoState, SSO_COOKIE } from "@/lib/federation/sso";
import { redirectGet } from "@/lib/security/headers";

type Params = { params: Promise<{ idpId: string }> };

/**
 * The IdP POSTs its signed response here, from its own site, so the browser
 * doesn't send our cookie. It's parked and the browser comes back as a GET,
 * which carries the cookie that ties the answer to the browser that asked.
 */
export async function POST(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "sso-acs", 30, 60);
      const { idpId } = await params;
      const form = await request.formData();
      const samlResponse = form.get("SAMLResponse");
      const relayState = form.get("RelayState");
      if (typeof samlResponse !== "string" || typeof relayState !== "string") throw new AppError("Invalid SAML response", 400, "invalid_request");
      const parked = await parkSamlResponse(samlResponse, relayState);
      const url = new URL(`/api/sso/saml/${encodeURIComponent(idpId)}/acs`, getEnv().APP_URL);
      url.searchParams.set("pending", parked);
      return redirectGet(url);
    });
  } catch (error) {
    return errorResponse(error);
  }
}

export async function GET(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "sso-callback", 30, 60);
      const { idpId } = await params;
      return finishResponse(request, async () => {
        const state = readSsoState(request.cookies.get(SSO_COOKIE)?.value);
        const pending = request.nextUrl.searchParams.get("pending");
        if (!state || !pending) throw new AppError("That sign-in has expired; try again", 400, "sso_state");
        const { idp, claims } = await finishSaml(state, idpId, pending);
        const result = await completeFederatedSignIn(idp, claims, { ...requestMeta(request), userAgent: request.headers.get("user-agent") });
        return { sessionToken: result.sessionToken, returnTo: state.returnTo };
      });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
