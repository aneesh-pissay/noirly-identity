import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { enforceRateLimit } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { exportIdentityData } from "@/lib/account/closure";
import { jsonResponse } from "@/lib/security/headers";
import { securitySession } from "@/lib/security/security-session";

/** Everything Identity holds about you, as a JSON download (offered before closing the account). */
export async function GET(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "auth-export", 5, 600);
      const { ctx } = await securitySession();
      const response = jsonResponse(await exportIdentityData(ctx.userId));
      response.headers.set("Content-Disposition", `attachment; filename="noirly-identity-${new Date().toISOString().slice(0, 10)}.json"`);
      return response;
    });
  } catch (error) {
    return errorResponse(error);
  }
}
