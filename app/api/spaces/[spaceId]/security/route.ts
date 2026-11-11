import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { spacesUser } from "@/lib/spaces/http";
import { getOrgSecurity, PRIMARY_METHODS, setOrgSecurity } from "@/lib/spaces/org-security";

type Params = { params: Promise<{ spaceId: string }> };

/** The organization's security policies (members can see them). */
export async function GET(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: false });
      const { spaceId } = await params;
      return jsonResponse(await getOrgSecurity(userId, spaceId));
    });
  } catch (error) {
    return errorResponse(error);
  }
}

const bodySchema = z
  .object({
    allowedMethods: z.array(z.enum(PRIMARY_METHODS)).max(PRIMARY_METHODS.length).optional(),
    sessionPolicy: z.object({ idleSeconds: z.number().int().nullable(), absoluteSeconds: z.number().int().nullable() }).optional(),
  })
  .refine((v) => v.allowedMethods !== undefined || v.sessionPolicy !== undefined);

/** Admins with the settings area: allowed sign-in methods and session lifetimes. */
export async function PATCH(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: true });
      const { spaceId } = await params;
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Invalid security settings", 400, "invalid_request");
      return jsonResponse(await setOrgSecurity(userId, spaceId, parsed.data));
    });
  } catch (error) {
    return errorResponse(error);
  }
}
