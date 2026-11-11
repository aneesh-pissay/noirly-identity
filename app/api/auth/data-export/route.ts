import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { downloadDataExport, listDataExports, requestDataExport } from "@/lib/account/data-export";
import { jsonResponse } from "@/lib/security/headers";
import { securitySession } from "@/lib/security/security-session";

/** Your data exports (with `?download=<id>`, the bundle itself). */
export async function GET(request: NextRequest) {
  try {
    return await withDb(async () => {
      const { ctx } = await securitySession();
      const id = request.nextUrl.searchParams.get("download");
      if (!id) return jsonResponse({ exports: await listDataExports(ctx.userId) });
      const response = jsonResponse(await downloadDataExport(ctx.userId, id));
      response.headers.set("Content-Disposition", `attachment; filename="noirly-data-${new Date().toISOString().slice(0, 10)}.json"`);
      return response;
    });
  } catch (error) {
    return errorResponse(error);
  }
}

/** Asks Identity and every Noirly app you use for your data, in one go (once a day). */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "data-export", 5, 3600);
      await enforceCsrfForCookieAuth(request);
      const { ctx } = await securitySession();
      return jsonResponse(await requestDataExport(ctx.userId), { status: 202 });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
