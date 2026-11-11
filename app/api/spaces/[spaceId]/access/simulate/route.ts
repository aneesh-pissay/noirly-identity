import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { spacesUser } from "@/lib/spaces/http";
import { requireAccessAdmin } from "@/lib/authz/admin";
import { explain, validPermission } from "@/lib/authz/engine";

type Params = { params: Promise<{ spaceId: string }> };

const bodySchema = z.object({
  subjectType: z.enum(["user", "service"]),
  subjectId: z.string().length(24),
  permission: z.string().max(100),
  resource: z.string().max(200).nullable().optional(),
  // "What if": a moment, a device, a country, a sign-in level.
  context: z
    .object({
      at: z.string().datetime().optional(),
      deviceTrusted: z.boolean().optional(),
      country: z.string().length(2).optional(),
      acr: z.string().max(100).optional(),
    })
    .optional(),
});

/**
 * Policy simulation (admins with the access area): can this person or
 * service account do this, on this resource, and why? Answers with the
 * assignments that granted it and, for every one that didn't apply, the
 * reason (an expiry, a resource, a condition), so access is easy to debug.
 */
export async function POST(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: true });
      const { spaceId } = await params;
      await requireAccessAdmin(spaceId, userId);
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success || !validPermission(parsed.data.permission)) throw new AppError('Give a subject and a permission like "invoice:read"', 400, "invalid_request");
      const { subjectType, subjectId, permission, resource, context } = parsed.data;
      const decision = await explain(spaceId, { type: subjectType, id: subjectId }, permission, resource ?? null, {
        now: context?.at ? new Date(context.at) : undefined,
        deviceTrusted: context?.deviceTrusted,
        country: context?.country?.toUpperCase(),
        acr: context?.acr,
      });
      return jsonResponse(decision);
    });
  } catch (error) {
    return errorResponse(error);
  }
}
