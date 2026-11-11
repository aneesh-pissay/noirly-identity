import { NextRequest, NextResponse } from "next/server";
import { errorResponse, oauthRedirectError } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, readJsonBody, requestMeta } from "@/lib/api/request";
import { recordEvent } from "@/lib/audit/event-log";
import { consentGivenAgain } from "@/lib/account/app-access";
import { resolveOrganization } from "@/lib/oauth/org-context";
import { validateSession } from "@/lib/sessions/session-service";
import { withDb } from "@/lib/api/with-db";
import {
  createAuthorizationCode,
  validateAuthorizeRequest,
} from "@/lib/oauth/authorize";
import { applySecurityHeaders, redirectGet } from "@/lib/security/headers";
import { getSessionTokenFromCookies } from "@/lib/security/cookies";
import { consentSchema } from "@/lib/validation/schemas";
import { getEnv } from "@/lib/config/env";

export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceCsrfForCookieAuth(request);
      const body = await readJsonBody(request);
      const parsed = consentSchema.safeParse(body);
      if (!parsed.success) {
        return applySecurityHeaders(
          NextResponse.json(
            {
              error: "invalid_request",
              error_description: "Invalid consent payload",
            },
            { status: 400 },
          ),
        );
      }

      const data = parsed.data;
      const validated = await validateAuthorizeRequest({
        client_id: data.client_id,
        redirect_uri: data.redirect_uri,
        response_type: "code",
        scope: data.scope,
        state: data.state,
        code_challenge: data.code_challenge,
        code_challenge_method: data.code_challenge_method,
        nonce: data.nonce,
        resource: data.resource,
      });

      if (data.decision === "deny") {
        return oauthRedirectError(
          data.redirect_uri,
          "access_denied",
          "The resource owner denied the request",
          data.state,
        );
      }

      const sessionToken = await getSessionTokenFromCookies();
      // Still a member of the organization the request named? (lib/oauth/org-context.ts)
      let organizationId: string | null = null;
      if (data.organization) {
        const ctx = await validateSession(sessionToken);
        const org = ctx ? await resolveOrganization(ctx.userId, data.organization) : null;
        if (!org) return oauthRedirectError(data.redirect_uri, "access_denied", "Choose an organization you belong to", data.state);
        organizationId = org.id;
      }
      const { code, userId } = await createAuthorizationCode({
        sessionToken,
        clientId: data.client_id,
        redirectUri: data.redirect_uri,
        scope: validated.scopeString,
        codeChallenge: data.code_challenge,
        codeChallengeMethod: data.code_challenge_method,
        nonce: data.nonce,
        resources: validated.resources,
        organizationId,
      });
      await consentGivenAgain(userId, data.client_id);
      await recordEvent({ action: "oauth.consent_granted", subjectId: userId, clientId: data.client_id, request: requestMeta(request), data: { scope: validated.scopeString } });

      const redirect = new URL(data.redirect_uri);
      redirect.searchParams.set("code", code);
      // RFC 9207: the issuer, against mix-up attacks.
      redirect.searchParams.set("iss", getEnv().OIDC_ISSUER.replace(/\/$/, ""));
      if (data.state) redirect.searchParams.set("state", data.state);
      return redirectGet(redirect);
    });
  } catch (error) {
    return errorResponse(error);
  }
}
