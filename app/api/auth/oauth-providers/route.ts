import { jsonResponse } from "@/lib/security/headers";
import { PROVIDER_SIGN_IN_ENABLED } from "@/lib/auth/provider-login";
import { getEnv } from "@/lib/config/env";
import { isGoogleOAuthConfigured } from "@/lib/auth/google";
import { isAppleConfigured } from "@/lib/auth/apple";
import { isProviderConfigured } from "@/lib/auth/oauth-providers";

/**
 * Which providers can be used to sign in, for sign-in pages here and in other
 * Noirly apps (Flow and Ledger hide Google One Tap when Google is false).
 * Providers are only ever linked, never used to sign in, so every one is off.
 */
export async function GET() {
  const google = PROVIDER_SIGN_IN_ENABLED && isGoogleOAuthConfigured();
  const response = jsonResponse({
    google,
    googleClientId: google ? getEnv().GOOGLE_CLIENT_ID : null,
    apple: PROVIDER_SIGN_IN_ENABLED && isAppleConfigured(),
    microsoft: PROVIDER_SIGN_IN_ENABLED && isProviderConfigured("microsoft"),
    github: PROVIDER_SIGN_IN_ENABLED && isProviderConfigured("github"),
  });
  response.headers.set("Access-Control-Allow-Origin", "*");
  return response;
}
