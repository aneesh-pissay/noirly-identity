import { NextRequest, NextResponse } from "next/server";
import { AppError, errorResponse, OAuthError, oauthRedirectError } from "@/lib/api/errors";
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
import { ACR_MFA, acrFor, satisfiesAcr } from "@/lib/auth/acr";
import { factorCount, factorCounts, isMfaRequired } from "@/lib/security/factors";
import { enrollmentState } from "@/lib/security/enrollment";
import { Session } from "@/models/Session";
import { consentRequiredAgain, hasGrantedScopes } from "@/lib/account/app-access";
import { parseClaimsRequest, scopesForClaims } from "@/lib/oidc/claims-request";
import { subjectFromIdTokenHint } from "@/lib/oidc/id-token-hint";
import { mayUseApp } from "@/lib/oauth/access-policy";
import { resolveOrganization } from "@/lib/oauth/org-context";
import { orgAllowsApp } from "@/lib/spaces/org-apps";
import { signInMeetsOrgMethods } from "@/lib/spaces/org-security";
import { assertExactRedirectUri, getActiveClient } from "@/lib/oauth/clients";

function buildLoginRedirect(
  requestUrl: string,
  popup: boolean,
  selectAccount: boolean,
  reauth = false,
): string {
  const env = getEnv();
  const login = new URL("/login", env.APP_URL);
  login.searchParams.set("return_to", requestUrl);
  if (popup) login.searchParams.set("popup", "1");
  if (selectAccount) login.searchParams.set("select_account", "1");
  // A fresh sign-in, even with a session: no "continue as" shortcut.
  if (reauth) login.searchParams.set("reauth", "1");
  return login.toString();
}

/** Sends the browser to sign in, remembering where to come back to. */
function loginResponse(target: string, returnUrl: string) {
  const response = redirectGet(target);
  response.cookies.set("noirly_oauth_return", returnUrl, {
    httpOnly: false,
    sameSite: "lax",
    secure: isProduction(),
    path: "/",
    maxAge: 60 * 60,
  });
  return response;
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
  // `resource` may repeat (RFC 8707): kept as one space-separated value.
  const flatten = (params: URLSearchParams) => {
    const out = Object.fromEntries(params.entries());
    const resources = params.getAll("resource").flatMap((r) => r.split(/\s+/)).filter(Boolean);
    if (resources.length) out.resource = resources.join(" ");
    return out;
  };
  const fromQuery = flatten(request.nextUrl.searchParams);
  if (fromQuery.client_id && fromQuery.response_type) {
    return fromQuery;
  }
  if (request.method !== "POST") {
    return fromQuery;
  }
  return flatten(await readFormBody(request));
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

      // Request objects aren't supported: say so to a known app at its own
      // redirect URI (OIDC Core 6.1), rather than ignoring what they asked.
      if (params.request || params.request_uri) {
        try {
          assertExactRedirectUri(await getActiveClient(params.client_id), params.redirect_uri);
        } catch (error) {
          return errorResponse(error);
        }
        return params.request
          ? oauthRedirectError(params.redirect_uri, "request_not_supported", "Request objects are not supported", params.state)
          : oauthRedirectError(params.redirect_uri, "request_uri_not_supported", "request_uri is not supported", params.state);
      }

      let validated;
      try {
        validated = await validateAuthorizeRequest(params);
      } catch (error) {
        // Scope and resource are checked after the client and redirect URI, so
        // those errors go back to the app (RFC 6749 §4.1.2.1, RFC 8707).
        if (error instanceof OAuthError && (error.error === "invalid_scope" || error.error === "invalid_target")) {
          return oauthRedirectError(params.redirect_uri, error.error, error.errorDescription ?? error.error, params.state);
        }
        // Do not redirect on invalid client/redirect — prevent open redirects.
        return errorResponse(error);
      }

      // The `claims` parameter (lib/oidc/claims-request.ts): claims asked for
      // on their own become their scopes, which consent and the grant cover.
      let claimsRequest;
      try {
        claimsRequest = parseClaimsRequest(params.claims);
      } catch (error) {
        if (error instanceof OAuthError) return oauthRedirectError(params.redirect_uri, error.error, error.errorDescription ?? error.error, params.state);
        throw error;
      }
      const addedScopes = scopesForClaims(claimsRequest, validated.scopes, validated.client.allowedScopes);
      if (addedScopes.length) {
        validated ={ ...validated, scopes: [...validated.scopes, ...addedScopes], scopeString: [...validated.scopes, ...addedScopes].join(" ") };
      }

      const sessionToken = await getSessionTokenFromCookies();
      const session = await validateSession(sessionToken);
      const forceAccountPicker = params.prompt === "select_account";
      const authorizeUrl = authorizeUrlFromRequest(request);

      // prompt=login: sign in again however recently they did; back here, the new sign-in must be after now.
      if (params.prompt === "login") {
        const back = new URL(authorizeUrl);
        back.searchParams.delete("prompt");
        back.searchParams.set("noirly_auth_after", String(Date.now()));
        return loginResponse(buildLoginRedirect(back.toString(), display === "popup", false, true), back.toString());
      }

      if (!session && params.prompt === "none") {
        return oauthRedirectError(
          params.redirect_uri,
          "login_required",
          "Authentication required",
          params.state,
        );
      }

      if (!session || forceAccountPicker) {
        return loginResponse(buildLoginRedirect(authorizeUrl, display === "popup", forceAccountPicker), authorizeUrl);
      }

      // The app's access policy (lib/oauth/access-policy.ts): anyone, chosen spaces, or an allowlist.
      if (!(await mayUseApp(validated.client, session.userId))) {
        if (params.prompt === "none") return oauthRedirectError(params.redirect_uri, "access_denied", "This account doesn't have access to this app", params.state);
        const denied = new URL("/no-access", getEnv().APP_URL);
        denied.searchParams.set("client_id", validated.client.clientId);
        return redirectGet(denied);
      }

      // `claims` or `id_token_hint` named a particular account: only that one may answer.
      const expectedSub = claimsRequest.sub ?? (await subjectFromIdTokenHint(params.id_token_hint));
      if (expectedSub && expectedSub !== session.userId) {
        if (params.prompt === "none") return oauthRedirectError(params.redirect_uri, "login_required", "A different account is signed in", params.state);
        return loginResponse(buildLoginRedirect(authorizeUrl, display === "popup", true), authorizeUrl);
      }

      // Organization context (lib/oauth/org-context.ts): tokens scoped to one of the person's organizations.
      let organizationId: string | null = null;
      if (params.organization) {
        const org = params.organization === "select" ? null : await resolveOrganization(session.userId, params.organization);
        if (!org) {
          if (params.prompt === "none") {
            return oauthRedirectError(params.redirect_uri, params.organization === "select" ? "interaction_required" : "access_denied", "Choose an organization you belong to", params.state);
          }
          const picker = new URL("/choose-organization", getEnv().APP_URL);
          picker.searchParams.set("return_to", authorizeUrl);
          return redirectGet(picker);
        }
        organizationId = org.id;
        // The organization's allowed sign-in methods (lib/spaces/org-security.ts): sign in again with one.
        const methods = await signInMeetsOrgMethods(org.id, session.session.methods);
        if (!methods.ok) {
          if (params.prompt === "none") return oauthRedirectError(params.redirect_uri, "login_required", "This organization needs another way of signing in", params.state);
          const back = new URL(authorizeUrl);
          back.searchParams.set("noirly_auth_after", String(Date.now()));
          return loginResponse(buildLoginRedirect(back.toString(), display === "popup", false, true), back.toString());
        }
        // The organization's own app rules (lib/spaces/org-apps.ts).
        if (!(await orgAllowsApp(org.id, session.userId, validated.client))) {
          if (params.prompt === "none") return oauthRedirectError(params.redirect_uri, "access_denied", "This organization doesn't allow this app for this account", params.state);
          const denied = new URL("/no-access", getEnv().APP_URL);
          denied.searchParams.set("client_id", validated.client.clientId);
          return redirectGet(denied);
        }
      }

      // How recent and how strong the sign-in is, against what the app asked for.
      const authenticatedAt = session.session.authenticatedAt.getTime();
      const tooOld =
        (params.max_age !== undefined && Date.now() - authenticatedAt > params.max_age * 1000) ||
        (params.noirly_auth_after !== undefined && authenticatedAt < params.noirly_auth_after);
      if (tooOld) {
        if (params.prompt === "none") return oauthRedirectError(params.redirect_uri, "login_required", "A more recent sign-in is required", params.state);
        return loginResponse(buildLoginRedirect(authorizeUrl, display === "popup", false, true), authorizeUrl);
      }
      const requestedAcr = (params.acr_values ?? "").split(/\s+/).filter(Boolean);
      // An essential `acr` in `claims` is a step-up like acr_values.
      requestedAcr.push(...claimsRequest.essentialAcr);
      // A second step the app or the person's spaces require, rather than one the app asked for this time.
      let spacePolicy = await isMfaRequired(session.userId);
      let overdue = false;
      if (spacePolicy && !validated.client.requireMfa) {
        // Someone who hasn't set one up yet has a grace period: nudged once per session on the way, then let through.
        const enrollment = await enrollmentState(session.userId);
        if (enrollment.state === "grace") {
          spacePolicy = false;
          const firstTime = await Session.updateOne({ _id: session.session._id, mfaNudgedAt: null }, { $set: { mfaNudgedAt: new Date() } });
          if (firstTime.modifiedCount === 1 && params.prompt !== "none") {
            const nudge = new URL("/account/security", getEnv().APP_URL);
            nudge.searchParams.set("enroll", "grace");
            nudge.searchParams.set("return_to", authorizeUrl);
            nudge.hash = "security-title";
            return redirectGet(nudge);
          }
        }
        overdue = enrollment.state === "overdue";
      }
      const policy = Boolean(validated.client.requireMfa) || spacePolicy;
      if (policy) requestedAcr.push(ACR_MFA);
      if (!satisfiesAcr(acrFor(session.session.methods), requestedAcr)) {
        if (params.prompt === "none") return oauthRedirectError(params.redirect_uri, "interaction_required", "A second sign-in step is required", params.state);
        if (factorCount(await factorCounts(session.userId)) === 0) {
          // Required: the person sets one up, then carries on to the app.
          if (policy) {
            const setUp = new URL("/account/security", getEnv().APP_URL);
            if (validated.client.requireMfa) setUp.searchParams.set("mfa_for", validated.client.clientId);
            // The grace period is over: apps stay closed until one is set up.
            if (overdue) setUp.searchParams.set("enroll", "overdue");
            setUp.searchParams.set("return_to", authorizeUrl);
            setUp.hash = "security-title";
            return redirectGet(setUp);
          }
          // Only asked for: the app hears it can't be met, rather than the person being stuck.
          return oauthRedirectError(params.redirect_uri, "unmet_authentication_requirements", "This account has no second sign-in step set up", params.state);
        }
        const stepUp = new URL("/api/auth/step-up", getEnv().APP_URL);
        stepUp.searchParams.set("return_to", authorizeUrl);
        return redirectGet(stepUp);
      }

      const needsConsent =
        validated.client.requireConsent || params.prompt === "consent" ||
        // The person removed this app's access: it asks again, whatever it normally does.
        (await consentRequiredAgain(session.userId, validated.client.clientId));

      // Silent sign-in can't show a consent page, but needn't: nothing new is
      // shared when the person already gave this app every scope it asks for.
      const silentlyCovered = needsConsent && params.prompt === "none" &&
        (await hasGrantedScopes(session.userId, validated.client.clientId, validated.scopeString));

      if (needsConsent && !silentlyCovered) {
        if (params.prompt === "none") {
          return oauthRedirectError(
            params.redirect_uri,
            "consent_required",
            "Consent required",
            params.state,
          );
        }
        const forConsent = new URLSearchParams(request.nextUrl.searchParams);
        if (params.resource) forConsent.set("resource", params.resource);
        // Includes scopes the `claims` parameter added, so the person sees them.
        forConsent.set("scope", validated.scopeString);
        return redirectGet(buildConsentRedirect(forConsent));
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
          resources: validated.resources,
          organizationId,
        }));
      } catch (error) {
        // Signed up but not verified yet: verify first, then come back here.
        if (error instanceof AppError && error.code === "email_not_verified") {
          if (params.prompt === "none") return oauthRedirectError(params.redirect_uri, "interaction_required", "The email address needs confirming first", params.state);
          const checkEmail = new URL("/check-email", getEnv().APP_URL);
          checkEmail.searchParams.set("return_to", authorizeUrl);
          return redirectGet(checkEmail);
        }
        throw error;
      }

      const redirect = new URL(params.redirect_uri);
      redirect.searchParams.set("code", code);
      // RFC 9207: the issuer, against mix-up attacks.
      redirect.searchParams.set("iss", getEnv().OIDC_ISSUER.replace(/\/$/, ""));
      if (params.state) redirect.searchParams.set("state", params.state);
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
