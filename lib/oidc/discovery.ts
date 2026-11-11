import { getEnv } from "@/lib/config/env";
import { ACR_VALUES } from "@/lib/auth/acr";
import { CLAIM_SCOPE, ID_TOKEN_BASE_CLAIMS } from "@/lib/oidc/claims-request";
import { CODE_CHALLENGE_METHODS, DISPLAY_VALUES, PROMPT_VALUES } from "@/lib/validation/schemas";
import { SUPPORTED_SCOPES } from "@/types";

/** How apps authenticate at the token, revocation and introspection endpoints (lib/oauth/token.ts). */
const CONFIDENTIAL_AUTH = ["client_secret_basic", "client_secret_post"] as const;

/**
 * The OpenID Provider metadata. Lists come from the same constants the
 * endpoints check against, so the document can't drift from what Identity
 * does; tests/discovery.test.ts checks the rest (every endpoint exists).
 */
export function buildDiscoveryDocument() {
  const env = getEnv();
  const issuer = env.OIDC_ISSUER.replace(/\/$/, "");

  return {
    issuer,
    authorization_endpoint: `${issuer}/api/oauth/authorize`,
    token_endpoint: `${issuer}/api/oauth/token`,
    userinfo_endpoint: `${issuer}/api/oidc/userinfo`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    end_session_endpoint: `${issuer}/api/oidc/logout`,
    revocation_endpoint: `${issuer}/api/oauth/revoke`,
    introspection_endpoint: `${issuer}/api/oauth/introspect`,
    // Not part of OIDC: a cheap "is the session still going?" check (app/api/oidc/session).
    noirly_session_check_endpoint: `${issuer}/api/oidc/session`,

    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token", "client_credentials"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    scopes_supported: [...SUPPORTED_SCOPES],
    claims_supported: [...new Set([...ID_TOKEN_BASE_CLAIMS, ...Object.keys(CLAIM_SCOPE), "organizations", "org_id", "org_slug", "org_role", "permissions"])],
    claim_types_supported: ["normal"],

    token_endpoint_auth_methods_supported: [...CONFIDENTIAL_AUTH, "none"],
    // Revocation: a public app names itself with client_id alone.
    revocation_endpoint_auth_methods_supported: [...CONFIDENTIAL_AUTH, "none"],
    introspection_endpoint_auth_methods_supported: [...CONFIDENTIAL_AUTH],
    code_challenge_methods_supported: [...CODE_CHALLENGE_METHODS],
    // RFC 9207: authorization responses (codes and errors) carry `iss`.
    authorization_response_iss_parameter_supported: true,

    // Step-up: ask for a level with acr_values, or a recent sign-in with max_age or prompt=login.
    acr_values_supported: [...ACR_VALUES],
    prompt_values_supported: [...PROMPT_VALUES],
    display_values_supported: [...DISPLAY_VALUES],
    // Claims asked for on their own become their scopes, so consent covers them (lib/oidc/claims-request.ts).
    claims_parameter_supported: true,
    request_parameter_supported: false,
    request_uri_parameter_supported: false,

    // Coordinated logout (lib/oidc/backchannel-logout.ts); `sid` is in every ID token.
    backchannel_logout_supported: true,
    backchannel_logout_session_supported: true,
    frontchannel_logout_supported: true,
    frontchannel_logout_session_supported: true,
  };
}
