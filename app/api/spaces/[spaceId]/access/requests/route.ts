import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { spacesUser } from "@/lib/spaces/http";
import { cancelRequest, decideRequest, listRequests, requestElevation } from "@/lib/authz/elevation";

type Params = { params: Promise<{ spaceId: string }> };

/** Requests for temporary access: admins see all, members their own. */
export async function GET(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: false });
      const { spaceId } = await params;
      return jsonResponse({ requests: await listRequests(userId, spaceId) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}

const id = z.string().length(24);
const bodySchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("request"), roleId: id, resource: z.string().max(200).optional(), reason: z.string().max(300), durationMinutes: z.number().int() }),
  z.object({ action: z.literal("approve"), requestId: id }),
  z.object({ action: z.literal("deny"), requestId: id }),
  z.object({ action: z.literal("cancel"), requestId: id }),
]);

export async function POST(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: true });
      const { spaceId } = await params;
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Invalid access request", 400, "invalid_request");
      const body = parsed.data;
      const meta = requestMeta(request);
      if (body.action === "request") await requestElevation(userId, spaceId, body, meta);
      if (body.action === "approve") await decideRequest(userId, spaceId, body.requestId, true, meta);
      if (body.action === "deny") await decideRequest(userId, spaceId, body.requestId, false, meta);
      if (body.action === "cancel") await cancelRequest(userId, spaceId, body.requestId);
      return jsonResponse({ requests: await listRequests(userId, spaceId) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
