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
import { frontchannelLogoutUrls } from "@/lib/oidc/backchannel-logout";
import { readIdTokenHint } from "@/lib/oidc/id-token-hint";
import { recordEvent, type RequestMeta } from "@/lib/audit/event-log";

export async function performLogout(input: {
  idTokenHint?: string | null;
  postLogoutRedirectUri?: string | null;
  clientId?: string | null;
  state?: string | null;
  request?: RequestMeta;
}): Promise<{ redirectTo: string | null; cleared: boolean; frontchannelLogoutUrls: string[] }> {
  let redirectTo: string | null = null;
  if (input.postLogoutRedirectUri) {
    // The app is named by client_id, or by the ID token it sent as a hint (RP-Initiated Logout 2).
    const hinted = await readIdTokenHint(input.idTokenHint);
    if (input.clientId && hinted && hinted.clientId !== input.clientId) throw new OAuthError("invalid_request", "client_id does not match id_token_hint");
    const clientId = input.clientId || hinted?.clientId;
    if (!clientId) throw new OAuthError("invalid_request", "client_id or id_token_hint is required when using post_logout_redirect_uri");
    const client = await getActiveClient(clientId);
    assertPostLogoutRedirectUri(client, input.postLogoutRedirectUri);
    const url = new URL(input.postLogoutRedirectUri);
    if (input.state) url.searchParams.set("state", input.state);
    redirectTo = url.toString();
  }
  const sessionToken = await getSessionTokenFromCookies();
  const ctx = await validateSession(sessionToken);
  let frontchannel: string[] = [];
  if (ctx) {
    await revokeAccessTokensForSession(ctx.session._id);
    await revokeRefreshTokensForSession(ctx.session._id);
    // Apps with a back-channel are told directly; the rest are signed out by
    // front-channel from this browser.
    const ended = await revokeSessionByToken(sessionToken!);
    if (ended.session) frontchannel = await frontchannelLogoutUrls(ended.session, ended.backchannelFailed);
    await recordEvent({ action: "auth.signed_out", subjectId: ctx.userId, clientId: input.clientId ?? null, request: input.request });
  }
  // The browser confirmed this operation with CSRF protection before reaching here.
  return { redirectTo, cleared: true, frontchannelLogoutUrls: frontchannel };
}
