import { NextRequest, after } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { spaceRoleSchema, spacesUser } from "@/lib/spaces/http";
import { ADMIN_AREAS, changeMemberRole, removeMember, setAdminAreas } from "@/lib/spaces/space-service";
import { notifySpaceChanged } from "@/lib/spaces/space-webhooks";

type Params = { params: Promise<{ spaceId: string; userId: string }> };

/** Change a member's role (admins; owners for anything involving owners). */
export async function PATCH(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId: actorId } = await spacesUser(request, { change: true });
      const { spaceId, userId } = await params;
      const body = z
        .object({ role: spaceRoleSchema.optional(), adminAreas: z.array(z.enum(ADMIN_AREAS)).max(4).nullable().optional() })
        .refine((v) => v.role !== undefined || v.adminAreas !== undefined)
        .safeParse(await readJsonBody(request));
      if (!body.success) throw new AppError("Choose a role", 400, "invalid_request");
      let space = body.data.role ? await changeMemberRole(actorId, spaceId, userId, body.data.role) : null;
      // Delegated administration (owners): limit an admin to some areas, or null for all.
      if (body.data.adminAreas !== undefined) space = await setAdminAreas(actorId, spaceId, userId, body.data.adminAreas);
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
