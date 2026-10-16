import { NextRequest, after } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { spacesUser } from "@/lib/spaces/http";
import { createSpace, listSpacesForUser } from "@/lib/spaces/space-service";
import { notifySpaceChanged } from "@/lib/spaces/space-webhooks";

/** Spaces you belong to. */
export async function GET(request: NextRequest) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: false });
      return jsonResponse({ spaces: await listSpacesForUser(userId) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}

/** Create a space; you become its owner. */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: true });
      const body = z.object({ name: z.string().trim().min(1).max(80) }).safeParse(await readJsonBody(request));
      if (!body.success) throw new AppError("Give the space a name (up to 80 characters)", 400, "invalid_request");
      const space = await createSpace({ ownerId: userId, name: body.data.name });
      after(() => notifySpaceChanged(space.id));
      return jsonResponse({ space }, { status: 201 });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
