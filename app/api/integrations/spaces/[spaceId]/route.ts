import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { requireSpacesClient } from "@/lib/spaces/integration-auth";
import { getSpace } from "@/lib/spaces/space-service";

type Params = { params: Promise<{ spaceId: string }> };

/** For apps: a space and its current members, to mirror into a linked team. */
export async function GET(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      await requireSpacesClient(request);
      const { spaceId } = await params;
      return jsonResponse({ space: await getSpace(spaceId) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
