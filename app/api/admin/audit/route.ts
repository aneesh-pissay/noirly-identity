import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { ADMIN_STREAM } from "@/lib/audit/chain";
import { exportEvents, recordEvent } from "@/lib/audit/event-log";
import { getRetention, setRetention } from "@/lib/audit/retention";
import { requireAdminUser } from "@/lib/auth/auth-service";
import { getSessionTokenFromCookies } from "@/lib/security/cookies";
import { jsonResponse } from "@/lib/security/headers";

const CSV_COLUMNS = ["stream", "seq", "at", "action", "actorId", "subjectId", "clientId", "ipAddress", "userAgent", "data", "prevHash", "hash"] as const;
const csvCell = (value: unknown) => {
  const text = value === null || value === undefined ? "" : typeof value === "string" ? value : JSON.stringify(value);
  // Quote everything; neutralise spreadsheet formulas.
  return `"${(/^[=+\-@]/.test(text) ? `'${text}` : text).replace(/"/g, '""')}"`;
};

/**
 * Admins: the audit retention settings, or (with `export`) authentication or
 * admin events between two moments, as JSON lines or CSV, with their hashes.
 */
export async function GET(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "admin-audit", 30, 60);
      const admin = await requireAdminUser(await getSessionTokenFromCookies());
      const params = request.nextUrl.searchParams;
      if (!params.get("export")) return jsonResponse(await getRetention());
      const kind = params.get("export");
      if (kind !== "auth" && kind !== "admin" && kind !== "all") throw new AppError("export is auth, admin or all", 400, "invalid_request");
      const from = new Date(params.get("from") ?? Date.now() - 30 * 86_400_000);
      const to = new Date(params.get("to") ?? Date.now());
      if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime()) || from >= to) throw new AppError("Give from and to as dates, from before to", 400, "invalid_request");
      const events = await exportEvents(kind, from, to);
      await recordEvent({ action: "audit.exported", stream: ADMIN_STREAM, actorId: admin.id, subjectId: null, request: requestMeta(request), data: { kind, from: from.toISOString(), to: to.toISOString(), count: events.length } });
      const csv = params.get("format") === "csv";
      const body = csv
        ? [CSV_COLUMNS.join(","), ...events.map((e) => CSV_COLUMNS.map((c) => csvCell(e[c as keyof typeof e])).join(","))].join("\n")
        : events.map((e) => JSON.stringify(e)).join("\n");
      return new Response(body, {
        headers: {
          "content-type": csv ? "text/csv; charset=utf-8" : "application/x-ndjson",
          "content-disposition": `attachment; filename="noirly-${kind}-events-${from.toISOString().slice(0, 10)}-${to.toISOString().slice(0, 10)}.${csv ? "csv" : "jsonl"}"`,
          "cache-control": "no-store",
        },
      });
    });
  } catch (error) {
    return errorResponse(error);
  }
}

/** Admins: set how long events are kept (days, at least 90; null keeps them forever). */
export async function PATCH(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "admin-audit-settings", 10, 60);
      await enforceCsrfForCookieAuth(request);
      const admin = await requireAdminUser(await getSessionTokenFromCookies());
      const parsed = z.object({ accountDays: z.number().int().nullable(), adminDays: z.number().int().nullable() }).safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Give accountDays and adminDays (or null)", 400, "invalid_request");
      const settings = await setRetention(parsed.data);
      await recordEvent({ action: "audit.retention_changed", stream: ADMIN_STREAM, actorId: admin.id, subjectId: null, request: requestMeta(request), data: settings });
      return jsonResponse(settings);
    });
  } catch (error) {
    return errorResponse(error);
  }
}
