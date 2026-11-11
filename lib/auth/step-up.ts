import { AppError } from "@/lib/api/errors";
import { newChallenge } from "@/lib/security/mfa";
import { factorCount, factorCounts } from "@/lib/security/factors";
import type { SessionContext } from "@/lib/sessions/session-service";

/**
 * Asking someone already signed in for their second step, because an app
 * asked for more than their session has (acr_values). They confirm on the
 * usual verification page; the session they have is then strengthened in
 * place (app/api/auth/mfa), so apps they're signed in to stay signed in.
 */
export async function startStepUp(ctx: SessionContext): Promise<string> {
  if (factorCount(await factorCounts(ctx.userId)) === 0) {
    throw new AppError("Set up an authenticator app, passkey or security key first.", 400, "no_second_factor");
  }
  return newChallenge({ userId: ctx.userId, purpose: "login-mfa", stepUpSessionId: String(ctx.session._id), priorMethods: ctx.session.methods });
}
