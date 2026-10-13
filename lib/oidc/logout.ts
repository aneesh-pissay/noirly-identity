import { OAuthError } from "@/lib/api/errors";
import {
  assertPostLogoutRedirectUri,
  getActiveClient,
} from "@/lib/oauth/clients";
import {
  getSessionTokenFromCookies,
} from "@/lib/security/cookies";
import {
  revokeSessionByToken,
  validateSession,
} from "@/lib/sessions/session-service";
import {
  revokeAccessTokensForSession,
  revokeRefreshTokensForSession,
} from "@/lib/tokens/token-service";

export async function performLogout(input: {
  idTokenHint?: string | null;
  postLogoutRedirectUri?: string | null;
  clientId?: string | null;
  state?: string | null;
}): Promise<{ redirectTo: string | null; cleared: boolean }> {
  let redirectTo: string | null = null;
  if (input.postLogoutRedirectUri) {
    if (!input.clientId) throw new OAuthError("invalid_request", "client_id is required when using post_logout_redirect_uri");
    const client = await getActiveClient(input.clientId);
    assertPostLogoutRedirectUri(client, input.postLogoutRedirectUri);
    const url = new URL(input.postLogoutRedirectUri);
    if (input.state) url.searchParams.set("state", input.state);
    redirectTo = url.toString();
  }
  const sessionToken = await getSessionTokenFromCookies();
  const ctx = await validateSession(sessionToken);
  if (ctx) {
    await revokeAccessTokensForSession(ctx.session._id);
    await revokeRefreshTokensForSession(ctx.session._id);
    await revokeSessionByToken(sessionToken!);
  }
  // The browser confirmed this operation with CSRF protection before reaching here.
  return { redirectTo, cleared: true };
}
