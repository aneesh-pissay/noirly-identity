import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { spacesUser } from "@/lib/spaces/http";
import { getOrgApps, removeOrgApp, setOrgApp, setOrgAppsMode } from "@/lib/spaces/org-apps";

type Params = { params: Promise<{ spaceId: string }> };

/** The apps the organization uses and who may open each (members can see; admins with the apps area manage). */
export async function GET(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: false });
      const { spaceId } = await params;
      return jsonResponse(await getOrgApps(userId, spaceId));
    });
  } catch (error) {
    return errorResponse(error);
  }
}

const bodySchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("mode"), mode: z.enum(["open", "listed"]) }),
  z.object({ action: z.literal("set"), appKey: z.string().min(1).max(80), access: z.enum(["everyone", "admins", "teams"]), teamIds: z.array(z.string().length(24)).max(50).optional() }),
  z.object({ action: z.literal("remove"), appKey: z.string().min(1).max(80) }),
]);

export async function POST(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: true });
      const { spaceId } = await params;
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Invalid app request", 400, "invalid_request");
      const body = parsed.data;
      if (body.action === "mode") return jsonResponse(await setOrgAppsMode(userId, spaceId, body.mode));
      if (body.action === "set") return jsonResponse(await setOrgApp(userId, spaceId, body));
      return jsonResponse(await removeOrgApp(userId, spaceId, body.appKey));
    });
  } catch (error) {
    return errorResponse(error);
  }
}
