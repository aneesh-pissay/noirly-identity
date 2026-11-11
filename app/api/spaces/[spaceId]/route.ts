import { NextRequest, after } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { spacesUser } from "@/lib/spaces/http";
import { deleteSpace, getSpaceForMember, renameSpace, setSpaceMfaRequired } from "@/lib/spaces/space-service";
import { notifySpaceChanged } from "@/lib/spaces/space-webhooks";

type Params = { params: Promise<{ spaceId: string }> };

/** A space and its members (members only). */
export async function GET(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: false });
      const { spaceId } = await params;
      return jsonResponse({ space: await getSpaceForMember(spaceId, userId) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}

/** Rename, or require a second step of every member (admins). */
export async function PATCH(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: true });
      const { spaceId } = await params;
      const body = z
        .object({ name: z.string().trim().min(1).max(80).optional(), requireMfa: z.boolean().optional() })
        .refine((value) => value.name !== undefined || value.requireMfa !== undefined)
        .safeParse(await readJsonBody(request));
      if (!body.success) throw new AppError("Give the space a name (up to 80 characters)", 400, "invalid_request");
      let space = body.data.name !== undefined ? await renameSpace(userId, spaceId, body.data.name) : null;
      if (body.data.requireMfa !== undefined) space = await setSpaceMfaRequired(userId, spaceId, body.data.requireMfa);
      after(() => notifySpaceChanged(spaceId));
      return jsonResponse({ space });
    });
  } catch (error) {
    return errorResponse(error);
  }
}

/** Delete (owners). Linked apps unlink their teams and keep them. */
export async function DELETE(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: true });
      const { spaceId } = await params;
      await deleteSpace(userId, spaceId);
      after(() => notifySpaceChanged(spaceId));
      return jsonResponse({ ok: true });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
