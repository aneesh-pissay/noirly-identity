import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { afterResponse } from "@/lib/api/after";
import { readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { spacesUser } from "@/lib/spaces/http";
import { transferOwnership } from "@/lib/spaces/space-service";
import { notifySpaceChanged } from "@/lib/spaces/space-webhooks";

type Params = { params: Promise<{ spaceId: string }> };

/** Hands the space to another member (owners): they become owner, you an admin. */
export async function POST(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: true });
      const { spaceId } = await params;
      const body = z.object({ userId: z.string().length(24) }).safeParse(await readJsonBody(request));
      if (!body.success) throw new AppError("Choose who takes it over", 400, "invalid_request");
      const space = await transferOwnership(userId, spaceId, body.data.userId);
      afterResponse(() => notifySpaceChanged(spaceId));
      return jsonResponse({ space });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
