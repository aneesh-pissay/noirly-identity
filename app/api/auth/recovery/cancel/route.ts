import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { cancelFactorRecovery } from "@/lib/security/recovery";

const bodySchema = z.object({ token: z.string().min(20).max(128) });

/** Cancels a lost-second-step request from the emailed link. A POST, so a mail scanner opening the link cancels nothing. */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-recovery-cancel", 10, 300);
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("This link is invalid", 400, "invalid_token");
      await cancelFactorRecovery(parsed.data.token, requestMeta(request));
      return jsonResponse({ ok: true });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
