import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { enforceRateLimit } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { recordEvent } from "@/lib/audit/event-log";
import { requireAdminUser } from "@/lib/auth/auth-service";
import { collectEvidence } from "@/lib/compliance/evidence";
import { getSessionTokenFromCookies } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";

/** Admins: live evidence for a compliance review (docs/compliance/CONTROLS.md). */
export async function GET(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "admin-evidence", 5, 60);
      const admin = await requireAdminUser(await getSessionTokenFromCookies());
      const evidence = await collectEvidence();
      await recordEvent({ action: "audit.exported", stream: "admin", actorId: admin.id, subjectId: null, data: { kind: "evidence" } });
      const response = jsonResponse(evidence);
      if (request.nextUrl.searchParams.get("download")) {
        response.headers.set("Content-Disposition", `attachment; filename="noirly-identity-evidence-${evidence.collectedAt.slice(0, 10)}.json"`);
      }
      return response;
    });
  } catch (error) {
    return errorResponse(error);
  }
}
