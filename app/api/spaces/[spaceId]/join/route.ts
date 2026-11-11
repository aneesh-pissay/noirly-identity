import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { afterResponse } from "@/lib/api/after";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { spacesUser } from "@/lib/spaces/http";
import { joinThroughDomain } from "@/lib/spaces/domains";
import { notifySpaceChanged } from "@/lib/spaces/space-webhooks";

type Params = { params: Promise<{ spaceId: string }> };

/** Joins as a member through a verified auto-join domain. */
export async function POST(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: true });
      const { spaceId } = await params;
      const role = await joinThroughDomain(userId, spaceId);
      afterResponse(() => notifySpaceChanged(spaceId));
      return jsonResponse({ spaceId, role });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
