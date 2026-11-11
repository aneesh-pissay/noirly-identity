import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { spacesUser } from "@/lib/spaces/http";
import { listInvitations } from "@/lib/spaces/invitations";

type Params = { params: Promise<{ spaceId: string }> };

/** Invitations not yet accepted (admins). */
export async function GET(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: false });
      const { spaceId } = await params;
      return jsonResponse({ invitations: await listInvitations(userId, spaceId) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
