import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { afterResponse } from "@/lib/api/after";
import { readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { spacesUser } from "@/lib/spaces/http";
import { notifySpaceChanged } from "@/lib/spaces/space-webhooks";
import { createTeam, deleteTeam, listTeams, setTeamMember, updateTeam } from "@/lib/spaces/teams";

type Params = { params: Promise<{ spaceId: string }> };

/** The space's teams (members can see them). */
export async function GET(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: false });
      const { spaceId } = await params;
      return jsonResponse({ teams: await listTeams(userId, spaceId) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}

const id = z.string().length(24);
const bodySchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("create"), name: z.string().min(1).max(80), parentId: id.nullable().optional() }),
  z.object({ action: z.literal("update"), teamId: id, name: z.string().min(1).max(80).optional(), parentId: id.nullable().optional() }),
  z.object({ action: z.literal("delete"), teamId: id }),
  z.object({ action: z.literal("add-member"), teamId: id, userId: id }),
  z.object({ action: z.literal("remove-member"), teamId: id, userId: id }),
]);

/** Admins (members area): create, rename or move, delete, and set who's in a team. */
export async function POST(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: true });
      const { spaceId } = await params;
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Invalid team request", 400, "invalid_request");
      const body = parsed.data;
      if (body.action === "create") await createTeam(userId, spaceId, body);
      if (body.action === "update") await updateTeam(userId, spaceId, body.teamId, body);
      if (body.action === "delete") await deleteTeam(userId, spaceId, body.teamId);
      if (body.action === "add-member") await setTeamMember(userId, spaceId, body.teamId, body.userId, true);
      if (body.action === "remove-member") await setTeamMember(userId, spaceId, body.teamId, body.userId, false);
      afterResponse(() => notifySpaceChanged(spaceId));
      return jsonResponse({ teams: await listTeams(userId, spaceId) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
