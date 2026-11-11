import { jsonResponse } from "@/lib/security/headers";
import { getEnv } from "@/lib/config/env";
import { isGoogleOAuthConfigured } from "@/lib/auth/google";
import { isAppleConfigured } from "@/lib/auth/apple";
import { isProviderConfigured } from "@/lib/auth/oauth-providers";

export async function GET() {
  const google = isGoogleOAuthConfigured();
  const response = jsonResponse({
    google,
    googleClientId: google ? getEnv().GOOGLE_CLIENT_ID : null,
    apple: isAppleConfigured(),
    microsoft: isProviderConfigured("microsoft"),
    github: isProviderConfigured("github"),
  });
  response.headers.set("Access-Control-Allow-Origin", "*");
  return response;
}
