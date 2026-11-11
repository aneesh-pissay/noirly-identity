import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { bulkInvite, bulkManage, importCsv } from "@/lib/directory/bulk";
import { listDeactivated, reactivateMember, requireMembersAdmin } from "@/lib/directory/lifecycle";
import { directoryReport, linkDirectoryId } from "@/lib/directory/reconcile";
import { createScimToken, listScimTokens, revokeScimToken, setScimAdminGroups } from "@/lib/scim/tokens";
import { jsonResponse } from "@/lib/security/headers";
import { spacesUser } from "@/lib/spaces/http";
import { canAdminister } from "@/lib/spaces/space-service";

type Params = { params: Promise<{ spaceId: string }> };

/** The space's directory: deactivated members, the reconciliation report and (for owners) SCIM connections. */
export async function GET(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: false });
      const { spaceId } = await params;
      await requireMembersAdmin(spaceId, userId);
      const scim = (await canAdminister(spaceId, userId, "domains")) ? await listScimTokens(userId, spaceId).catch(() => null) : null;
      return jsonResponse({ deactivated: await listDeactivated(userId, spaceId), report: await directoryReport(userId, spaceId), scim });
    });
  } catch (error) {
    return errorResponse(error);
  }
}

const role = z.enum(["member", "admin", "owner"]);
const bodySchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("invite"), emails: z.array(z.string().max(254)).min(1).max(500), role }),
  z.object({ action: z.literal("import_csv"), csv: z.string().min(1).max(1_000_000) }),
  z.object({
    action: z.literal("manage"),
    userIds: z.array(z.string().max(24)).min(1).max(500),
    change: z.discriminatedUnion("action", [
      z.object({ action: z.literal("remove") }),
      z.object({ action: z.literal("role"), role }),
      z.object({ action: z.literal("deactivate") }),
      z.object({ action: z.literal("reactivate") }),
      z.object({ action: z.literal("add_to_team"), teamId: z.string().length(24) }),
      z.object({ action: z.literal("remove_from_team"), teamId: z.string().length(24) }),
    ]),
  }),
  z.object({ action: z.literal("reactivate"), userId: z.string().length(24) }),
  z.object({ action: z.literal("link"), userId: z.string().length(24), externalId: z.string().min(1).max(300) }),
  z.object({ action: z.literal("scim_token"), name: z.string().min(1).max(80) }),
  z.object({ action: z.literal("scim_revoke"), tokenId: z.string().length(24) }),
  z.object({ action: z.literal("scim_admin_groups"), groups: z.array(z.string().max(100)).max(20) }),
]);

export async function POST(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: true });
      const { spaceId } = await params;
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Invalid request", 400, "invalid_request");
      const body = parsed.data;
      switch (body.action) {
        case "invite":
          return jsonResponse({ results: await bulkInvite(userId, spaceId, body.emails, body.role) });
        case "import_csv":
          return jsonResponse({ results: await importCsv(userId, spaceId, body.csv) });
        case "manage":
          return jsonResponse({ results: await bulkManage(userId, spaceId, body.userIds, body.change) });
        case "reactivate":
          await requireMembersAdmin(spaceId, userId);
          return jsonResponse(await reactivateMember(spaceId, body.userId, { actorId: userId, via: "admin" }));
        case "link":
          await linkDirectoryId(userId, spaceId, body.userId, body.externalId);
          return jsonResponse({ ok: true });
        case "scim_token":
          // The token is shown this once.
          return jsonResponse(await createScimToken(userId, spaceId, body.name), { status: 201 });
        case "scim_revoke":
          await revokeScimToken(userId, spaceId, body.tokenId);
          return jsonResponse({ ok: true });
        case "scim_admin_groups":
          return jsonResponse({ adminGroups: await setScimAdminGroups(userId, spaceId, body.groups) });
      }
    });
  } catch (error) {
    return errorResponse(error);
  }
}
