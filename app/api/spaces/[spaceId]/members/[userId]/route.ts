import { NextRequest, after } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { spaceRoleSchema, spacesUser } from "@/lib/spaces/http";
import { changeMemberRole, removeMember } from "@/lib/spaces/space-service";
import { notifySpaceChanged } from "@/lib/spaces/space-webhooks";

type Params = { params: Promise<{ spaceId: string; userId: string }> };

/** Change a member's role (admins; owners for anything involving owners). */
export async function PATCH(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId: actorId } = await spacesUser(request, { change: true });
      const { spaceId, userId } = await params;
      const body = z.object({ role: spaceRoleSchema }).safeParse(await readJsonBody(request));
      if (!body.success) throw new AppError("Choose a role", 400, "invalid_request");
      const space = await changeMemberRole(actorId, spaceId, userId, body.data.role);
      after(() => notifySpaceChanged(spaceId));
      return jsonResponse({ space });
    });
  } catch (error) {
    return errorResponse(error);
  }
}

/** Remove a member (admins), or leave (yourself). */
export async function DELETE(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId: actorId } = await spacesUser(request, { change: true });
      const { spaceId, userId } = await params;
      await removeMember(actorId, spaceId, userId);
      after(() => notifySpaceChanged(spaceId));
      return jsonResponse({ ok: true });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
