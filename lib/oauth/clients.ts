import { OAuthError } from "@/lib/api/errors";
import { OAuthClient, type OAuthClientDocument } from "@/models/OAuthClient";

export async function getActiveClient(
  clientId: string,
): Promise<OAuthClientDocument> {
  const client = await OAuthClient.findOne({ clientId }).select("+clientSecretHash +previousSecretHash");
  if (!client || client.status !== "active") {
    throw new OAuthError("invalid_client", "Unknown or inactive client", 401);
  }
  return client;
}

export function assertExactRedirectUri(
  client: OAuthClientDocument,
  redirectUri: string,
): void {
  if (!client.redirectUris.includes(redirectUri)) {
    throw new OAuthError(
      "invalid_request",
      "redirect_uri does not match registered values",
    );
  }
}

export function assertPostLogoutRedirectUri(
  client: OAuthClientDocument,
  uri: string,
): void {
  if (!client.postLogoutRedirectUris.includes(uri)) {
    throw new OAuthError(
      "invalid_request",
      "post_logout_redirect_uri is not registered",
    );
  }
}
