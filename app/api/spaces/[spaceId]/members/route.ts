import { NextRequest, after } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { spaceRoleSchema, spacesUser } from "@/lib/spaces/http";
import { addMemberByEmail } from "@/lib/spaces/space-service";
import { notifySpaceChanged } from "@/lib/spaces/space-webhooks";

type Params = { params: Promise<{ spaceId: string }> };

/** Add someone by their Noirly account email (admins). */
export async function POST(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: true });
      const { spaceId } = await params;
      const body = z
        .object({ email: z.string().trim().email().max(254), role: spaceRoleSchema.default("member") })
        .safeParse(await readJsonBody(request));
      if (!body.success) throw new AppError("Enter an email address", 400, "invalid_request");
      const space = await addMemberByEmail(userId, spaceId, body.data.email, body.data.role);
      after(() => notifySpaceChanged(spaceId));
      return jsonResponse({ space }, { status: 201 });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
