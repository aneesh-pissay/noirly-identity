import { errorResponse } from "@/lib/api/errors";
import { withDb } from "@/lib/api/with-db";
import { privacySummary } from "@/lib/account/privacy";
import { jsonResponse } from "@/lib/security/headers";
import { securitySession } from "@/lib/security/security-session";

/** What Identity holds about you, by kind: how much, why, and for how long. */
export async function GET() {
  try {
    return await withDb(async () => {
      const { ctx } = await securitySession();
      return jsonResponse({ categories: await privacySummary(ctx.userId) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
