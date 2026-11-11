import { NextRequest } from "next/server";
import { afterResponse } from "@/lib/api/after";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceRateLimit, readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { spacesUser } from "@/lib/spaces/http";
import { acceptInvitation, previewInvitation } from "@/lib/spaces/invitations";
import { notifySpaceChanged } from "@/lib/spaces/space-webhooks";

/** What an invitation link is for (the space and role), before joining. */
export async function GET(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "invitation-preview", 30, 60);
      const token = request.nextUrl.searchParams.get("token") ?? "";
      if (!token || token.length > 200) throw new AppError("This invitation has expired or was withdrawn. Ask for a new one.", 410, "invitation_gone");
      return jsonResponse({ invitation: await previewInvitation(token) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}

/** Joins the space, signed in to an account that owns the invited address. */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: true });
      const body = z.object({ token: z.string().min(10).max(200) }).safeParse(await readJsonBody(request));
      if (!body.success) throw new AppError("This invitation has expired or was withdrawn. Ask for a new one.", 410, "invitation_gone");
      const result = await acceptInvitation(userId, body.data.token);
      afterResponse(() => notifySpaceChanged(result.spaceId));
      return jsonResponse({ spaceId: result.spaceId });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
