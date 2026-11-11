import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { spaceRoleSchema, spacesUser } from "@/lib/spaces/http";
import { inviteToSpace } from "@/lib/spaces/invitations";

type Params = { params: Promise<{ spaceId: string }> };

/**
 * Invites someone by email (admins). They join when they open the emailed
 * link signed in to an account with that address (lib/spaces/invitations.ts).
 */
export async function POST(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: true });
      const { spaceId } = await params;
      const body = z
        .object({ email: z.string().trim().email().max(254), role: spaceRoleSchema.default("member") })
        .safeParse(await readJsonBody(request));
      if (!body.success) throw new AppError("Enter an email address", 400, "invalid_request");
      const { invitation } = await inviteToSpace(userId, spaceId, body.data.email, body.data.role);
      return jsonResponse({ invitation }, { status: 201 });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
