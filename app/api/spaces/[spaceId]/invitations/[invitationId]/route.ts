import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { spacesUser } from "@/lib/spaces/http";
import { revokeInvitation } from "@/lib/spaces/invitations";

type Params = { params: Promise<{ spaceId: string; invitationId: string }> };

/** Withdraws an invitation (admins): its link stops working. */
export async function DELETE(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: true });
      const { spaceId, invitationId } = await params;
      await revokeInvitation(userId, spaceId, invitationId);
      return jsonResponse({ ok: true });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
