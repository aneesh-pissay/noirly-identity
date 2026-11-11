import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { deleteAlertRule, listAlertRules, saveAlertRule } from "@/lib/audit/alert-rules";
import { requireAdminUser } from "@/lib/auth/auth-service";
import { getSessionTokenFromCookies } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";

/** Admins: alert rules on chosen events. */
export async function GET() {
  try {
    return await withDb(async () => {
      await requireAdminUser(await getSessionTokenFromCookies());
      return jsonResponse({ rules: await listAlertRules() });
    });
  } catch (error) {
    return errorResponse(error);
  }
}

const bodySchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("save"), id: z.string().length(24).optional(), name: z.string().max(80), actions: z.array(z.string().max(80)).max(30), emails: z.array(z.string().max(254)).max(10), enabled: z.boolean().optional() }),
  z.object({ action: z.literal("delete"), id: z.string().length(24) }),
]);

export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "admin-audit-alerts", 30, 60);
      await enforceCsrfForCookieAuth(request);
      const admin = await requireAdminUser(await getSessionTokenFromCookies());
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Invalid rule", 400, "invalid_request");
      if (parsed.data.action === "save") await saveAlertRule(admin.id, parsed.data);
      else await deleteAlertRule(parsed.data.id);
      return jsonResponse({ rules: await listAlertRules() });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
