import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { confirmMerge } from "@/lib/account/merge";
import { jsonResponse } from "@/lib/security/headers";

const bodySchema = z.object({ token: z.string().min(20).max(128) });

/**
 * The other account's owner confirms, with the link sent to its address.
 * The token is the proof; a POST, so a mail scanner opening the link
 * confirms nothing.
 */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-merge-confirm", 10, 300);
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("This link is invalid", 400, "invalid_token");
      return jsonResponse(await confirmMerge(parsed.data.token, requestMeta(request)));
    });
  } catch (error) {
    return errorResponse(error);
  }
}
