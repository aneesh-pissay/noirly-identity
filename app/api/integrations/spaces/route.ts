import { NextRequest, after } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { spaceRoleSchema } from "@/lib/spaces/http";
import { requireSpacesClient } from "@/lib/spaces/integration-auth";
import { createSpace } from "@/lib/spaces/space-service";
import { notifySpaceChanged } from "@/lib/spaces/space-webhooks";

const sub = z.string().regex(/^[a-f0-9]{24}$/i);

/**
 * For apps: turn an existing team into a space. The app vouches that `ownerSub`
 * asked for this and that `members` are its team (first-party apps only, by
 * the organizations grant). Members without a verified Noirly account are
 * skipped; the response lists who made it in.
 */
export async function POST(request: NextRequest) {
  try {
    return await withDb(async () => {
      await requireSpacesClient(request);
      const body = z
        .object({
          name: z.string().trim().min(1).max(80),
          ownerSub: sub,
          members: z.array(z.object({ sub, role: spaceRoleSchema })).max(500).default([]),
        })
        .safeParse(await readJsonBody(request));
      if (!body.success) throw new AppError("Invalid space", 400, "invalid_request");
      const space = await createSpace({
        ownerId: body.data.ownerSub,
        name: body.data.name,
        members: body.data.members.map((m) => ({ userId: m.sub, role: m.role })),
      });
      after(() => notifySpaceChanged(space.id));
      return jsonResponse({ space }, { status: 201 });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
