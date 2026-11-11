import { NextRequest } from "next/server";
import { z } from "zod";
import { Types } from "mongoose";
import { AppError, errorResponse } from "@/lib/api/errors";
import { readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { spacesUser } from "@/lib/spaces/http";
import { assignRole, deleteRole, listAccess, requireAccessAdmin, saveRole, setMemberAttributes, unassignRole } from "@/lib/authz/admin";
import { Organization } from "@/models/Organization";

type Params = { params: Promise<{ spaceId: string }> };

/** The organization's roles and who holds them (members can see; admins with the access area manage). */
export async function GET(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: false });
      const { spaceId } = await params;
      return jsonResponse(await listAccess(userId, spaceId));
    });
  } catch (error) {
    return errorResponse(error);
  }
}

const id = z.string().length(24);
const condition = z.object({ attribute: z.string().min(1).max(40), op: z.string().min(1).max(10), value: z.string().min(1).max(200) });
const bodySchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("save-role"), id: id.optional(), name: z.string().min(1).max(60), description: z.string().max(300).optional(), permissions: z.array(z.string().max(100)).max(200) }),
  z.object({ action: z.literal("delete-role"), roleId: id }),
  z.object({
    action: z.literal("assign"),
    roleId: id,
    subjectType: z.enum(["user", "team", "service"]),
    subjectId: id,
    resource: z.string().max(200).optional(),
    conditions: z.array(condition).max(10).optional(),
    expiresAt: z.string().datetime().nullable().optional(),
    reason: z.string().max(300).optional(),
  }),
  z.object({ action: z.literal("unassign"), assignmentId: id }),
  z.object({ action: z.literal("set-attributes"), userId: id, attributes: z.record(z.string(), z.string().max(100)) }),
  z.object({ action: z.literal("time-zone"), timeZone: z.string().max(60).nullable() }),
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
      if (body.action === "save-role") await saveRole(userId, spaceId, body, meta);
      if (body.action === "delete-role") await deleteRole(userId, spaceId, body.roleId, meta);
      if (body.action === "assign") await assignRole(userId, spaceId, body, meta);
      if (body.action === "unassign") await unassignRole(userId, spaceId, body.assignmentId, meta);
      if (body.action === "set-attributes") await setMemberAttributes(userId, spaceId, body.userId, body.attributes, meta);
      if (body.action === "time-zone") {
        await requireAccessAdmin(spaceId, userId);
        if (body.timeZone) {
          try {
            new Intl.DateTimeFormat("en", { timeZone: body.timeZone });
          } catch {
            throw new AppError("Unknown time zone", 400, "invalid_request");
          }
        }
        await Organization.updateOne({ _id: new Types.ObjectId(spaceId) }, { $set: { timeZone: body.timeZone } });
      }
      return jsonResponse(await listAccess(userId, spaceId));
    });
  } catch (error) {
    return errorResponse(error);
  }
}
