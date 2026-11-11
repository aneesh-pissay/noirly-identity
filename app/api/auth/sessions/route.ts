import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { clearSessionCookie } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";
import { securitySession } from "@/lib/security/security-session";
import { listDeviceSessions, signOutOfApp, signOutOtherSessions, signOutSessions } from "@/lib/sessions/devices";

const bodySchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("sign-out"), ids: z.array(z.string().length(24)).min(1).max(100) }),
  z.object({ action: z.literal("sign-out-others") }),
  // One app only: on one device (`sessionId`), or on every device when it's left out.
  z.object({ action: z.literal("sign-out-app"), clientId: z.string().min(1).max(200), sessionId: z.string().length(24).optional() }),
]);

/** The browsers and devices signed in to this account. */
export async function GET() {
  try {
    return await withDb(async () => {
      const { ctx } = await securitySession();
      return jsonResponse({ sessions: await listDeviceSessions(ctx.userId, String(ctx.session._id)) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}

/**
 * Signs out chosen sessions, or all but this one. No fresh sign-in needed:
 * someone who spots a stranger's session should be able to end it at once.
 */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-sessions", 20, 300);
      await enforceCsrfForCookieAuth(request);
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Choose which sessions to sign out", 400, "invalid_request");
      const { ctx } = await securitySession();
      const current = String(ctx.session._id);
      const meta = requestMeta(request);
      if (parsed.data.action === "sign-out-app") {
        const { ended } = await signOutOfApp(ctx.userId, parsed.data.clientId, parsed.data.sessionId ?? null, meta);
        return jsonResponse({ ended, sessions: await listDeviceSessions(ctx.userId, current) });
      }
      const result = parsed.data.action === "sign-out"
        ? await signOutSessions(ctx.userId, parsed.data.ids, current, meta)
        : await signOutOtherSessions(ctx.userId, current, meta);
      const response = jsonResponse({ ...result, sessions: result.includingThisOne ? [] : await listDeviceSessions(ctx.userId, current) });
      if (result.includingThisOne) await clearSessionCookie(response);
      return response;
    });
  } catch (error) {
    return errorResponse(error);
  }
}
