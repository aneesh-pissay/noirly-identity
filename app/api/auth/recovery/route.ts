import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { setSessionCookie } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";
import { MFA_COOKIE } from "@/lib/security/mfa";
import { finishFactorRecovery, recoveryStatus, sendRecoveryProof, startFactorRecovery } from "@/lib/security/recovery";

const bodySchema = z.object({ action: z.enum(["status", "send-code", "start", "finish"]), code: z.string().max(12).optional() });

/**
 * Lost second step, from the verification screen: the challenge cookie shows
 * the first step was passed. `status`, `start` the wait, or `finish` once
 * it's over (which signs in).
 */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-recovery", 20, 300);
      await enforceCsrfForCookieAuth(request);
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Invalid recovery request", 400, "invalid_request");
      const challenge = request.cookies.get(MFA_COOKIE)?.value ?? null;
      const meta = requestMeta(request);
      switch (parsed.data.action) {
        case "status":
          return jsonResponse(await recoveryStatus(challenge));
        case "send-code":
          await sendRecoveryProof(challenge);
          return jsonResponse({ sent: true });
        case "start":
          return jsonResponse(await startFactorRecovery(challenge, meta, parsed.data.code));
        case "finish": {
          const { sessionToken } = await finishFactorRecovery(challenge, meta);
          const response = jsonResponse({ ok: true });
          await setSessionCookie(response, sessionToken);
          response.cookies.set(MFA_COOKIE, "", { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict", path: "/", maxAge: 0 });
          return response;
        }
      }
    });
  } catch (error) {
    return errorResponse(error);
  }
}
