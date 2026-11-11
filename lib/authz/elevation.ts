import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { orgStream } from "@/lib/audit/chain";
import { recordEvent, type RequestMeta } from "@/lib/audit/event-log";
import { getEnv } from "@/lib/config/env";
import { sendEmail } from "@/lib/email/email-service";
import { buildNoticeEmail } from "@/lib/email/templates";
import { assignRole, requireAccessAdmin } from "@/lib/authz/admin";
import { AccessRequest, AuthzRole, RoleAssignment } from "@/models/Authz";
import { Organization } from "@/models/Organization";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { User } from "@/models/User";
import { canAdminister, roleIn } from "@/lib/spaces/space-service";

/**
 * Short-lived elevated access. A member asks for a role for a while (15
 * minutes to a week), saying why. An admin with the access area approves or
 * denies it; nobody approves their own. Approval creates an assignment that
 * expires by itself: the engine stops counting it at that moment, and
 * `sweepExpiredElevations` later removes it and logs that it ended.
 */

export const MIN_MINUTES = 15;
export const MAX_MINUTES = 7 * 24 * 60;

export type RequestView = {
  id: string;
  userId: string;
  roleId: string;
  role: string;
  resource: string;
  reason: string;
  durationMinutes: number;
  status: "pending" | "approved" | "denied" | "cancelled";
  requestedAt: string;
  expiresAt: string | null;
};

const oid = (id: string, what = "Request") => {
  if (!Types.ObjectId.isValid(id)) throw new AppError(`${what} not found`, 404, "not_found");
  return new Types.ObjectId(id);
};

async function view(r: { _id: Types.ObjectId; userId: Types.ObjectId; roleId: Types.ObjectId; resource?: string | null; reason: string; durationMinutes: number; status: string; createdAt: Date; assignmentId?: Types.ObjectId | null }): Promise<RequestView> {
  const [role, assignment] = await Promise.all([
    AuthzRole.findById(r.roleId).select("name").lean(),
    r.assignmentId ? RoleAssignment.findById(r.assignmentId).select("expiresAt").lean() : null,
  ]);
  return {
    id: String(r._id),
    userId: String(r.userId),
    roleId: String(r.roleId),
    role: role?.name ?? "(deleted role)",
    resource: r.resource ?? "*",
    reason: r.reason,
    durationMinutes: r.durationMinutes,
    status: r.status as RequestView["status"],
    requestedAt: r.createdAt.toISOString(),
    expiresAt: assignment?.expiresAt ? assignment.expiresAt.toISOString() : null,
  };
}

async function accessAdmins(spaceId: string) {
  const memberships = await OrganizationMembership.find({ organizationId: oid(spaceId, "Space"), role: { $in: ["owner", "admin"] } }).select("userId role adminAreas").lean();
  const ids = memberships.filter((m) => m.role === "owner" || !Array.isArray(m.adminAreas) || m.adminAreas.includes("access")).map((m) => m.userId);
  return User.find({ _id: { $in: ids }, status: "active" }).select("email").lean();
}

export async function requestElevation(userId: string, spaceId: string, input: { roleId: string; resource?: string; reason: string; durationMinutes: number }, meta: RequestMeta = {}): Promise<RequestView> {
  if (!(await roleIn(spaceId, userId))) throw new AppError("Space not found", 404, "not_found");
  const role = await AuthzRole.findOne({ _id: oid(input.roleId, "Role"), organizationId: oid(spaceId, "Space") }).lean();
  if (!role) throw new AppError("Role not found", 404, "not_found");
  const reason = input.reason.trim();
  if (reason.length < 5 || reason.length > 300) throw new AppError("Say why you need it (5 to 300 characters)", 400, "invalid_request");
  if (!Number.isInteger(input.durationMinutes) || input.durationMinutes < MIN_MINUTES || input.durationMinutes > MAX_MINUTES) {
    throw new AppError("Ask for 15 minutes up to a week", 400, "invalid_request");
  }
  if (await AccessRequest.exists({ organizationId: role.organizationId, userId: oid(userId, "User"), roleId: role._id, status: "pending" })) {
    throw new AppError("You already have a request for that role waiting", 409, "already_requested");
  }
  const created = await AccessRequest.create({ organizationId: role.organizationId, userId: oid(userId, "User"), roleId: role._id, resource: input.resource?.trim() || "*", reason, durationMinutes: input.durationMinutes });
  await recordEvent({ action: "authz.elevation_requested", stream: orgStream(spaceId), actorId: userId, subjectId: userId, request: meta, data: { requestId: String(created._id), role: role.name, durationMinutes: input.durationMinutes, reason, organizationId: spaceId } });
  const [org, requester, admins] = await Promise.all([Organization.findById(role.organizationId).select("name").lean(), User.findById(userId).select("displayName").lean(), accessAdmins(spaceId)]);
  const url = new URL("/spaces", getEnv().APP_URL).toString();
  await Promise.all(admins.map((admin) => sendEmail({
    to: admin.email,
    ...buildNoticeEmail({
      subject: `Access request in ${org?.name ?? "your space"}`,
      paragraphs: [`${requester?.displayName ?? "A member"} asked for ${role.name} for ${input.durationMinutes} minutes: "${reason}".`],
      action: { label: "Review it", url },
    }),
    meta: { kind: "access-request" },
  })));
  return view(created.toObject());
}

/** Admins see every request; anyone else sees their own. */
export async function listRequests(actorId: string, spaceId: string): Promise<RequestView[]> {
  if (!(await roleIn(spaceId, actorId))) throw new AppError("Space not found", 404, "not_found");
  const admin = await canAdminister(spaceId, actorId, "access");
  const requests = await AccessRequest.find({ organizationId: oid(spaceId, "Space"), ...(admin ? {} : { userId: oid(actorId, "User") }) }).sort({ createdAt: -1 }).limit(100).lean();
  return Promise.all(requests.map(view));
}

export async function decideRequest(actorId: string, spaceId: string, requestId: string, approve: boolean, meta: RequestMeta = {}): Promise<RequestView> {
  await requireAccessAdmin(spaceId, actorId);
  const request = await AccessRequest.findOne({ _id: oid(requestId), organizationId: oid(spaceId, "Space") });
  if (!request) throw new AppError("Request not found", 404, "not_found");
  if (request.status !== "pending") throw new AppError("That request has already been decided", 409, "already_decided");
  if (String(request.userId) === actorId) throw new AppError("Someone else has to approve your own request", 403, "self_approval");
  // Claimed once, even if two admins decide at the same moment.
  const claimed = await AccessRequest.findOneAndUpdate({ _id: request._id, status: "pending" }, { $set: { status: approve ? "approved" : "denied", decidedBy: oid(actorId, "User"), decidedAt: new Date() } }, { returnDocument: "after" });
  if (!claimed) throw new AppError("That request has already been decided", 409, "already_decided");
  if (approve) {
    if (!(await roleIn(spaceId, String(request.userId)))) {
      await AccessRequest.updateOne({ _id: request._id }, { $set: { status: "cancelled" } });
      throw new AppError("They're no longer in this space", 409, "not_in_space");
    }
    const assignment = await assignRole(actorId, spaceId, {
      roleId: String(request.roleId),
      subjectType: "user",
      subjectId: String(request.userId),
      resource: request.resource ?? "*",
      expiresAt: new Date(Date.now() + request.durationMinutes * 60_000).toISOString(),
      reason: request.reason,
      source: "elevation",
    }, meta);
    claimed.assignmentId = new Types.ObjectId(assignment.id);
    await claimed.save();
  }
  await recordEvent({ action: approve ? "authz.elevation_approved" : "authz.elevation_denied", stream: orgStream(spaceId), actorId, subjectId: String(request.userId), request: meta, data: { requestId, organizationId: spaceId } });
  const requester = await User.findById(request.userId).select("email").lean();
  const role = await AuthzRole.findById(request.roleId).select("name").lean();
  if (requester) {
    await sendEmail({
      to: requester.email,
      ...buildNoticeEmail({
        subject: approve ? `You have ${role?.name ?? "the role"} for ${request.durationMinutes} minutes` : "Your access request was declined",
        paragraphs: [approve ? `Your request for ${role?.name ?? "the role"} was approved. It ends by itself in ${request.durationMinutes} minutes.` : `Your request for ${role?.name ?? "the role"} was declined.`],
      }),
      meta: { kind: "access-request-decided" },
    });
  }
  return view(claimed.toObject());
}

/** The requester withdraws a pending request. */
export async function cancelRequest(userId: string, spaceId: string, requestId: string) {
  const result = await AccessRequest.updateOne({ _id: oid(requestId), organizationId: oid(spaceId, "Space"), userId: oid(userId, "User"), status: "pending" }, { $set: { status: "cancelled" } });
  if (!result.modifiedCount) throw new AppError("Request not found", 404, "not_found");
}

/**
 * Removes elevated assignments whose time is up and logs that each ended.
 * (They stopped counting at their expiry already; this tidies up.)
 */
export async function sweepExpiredElevations(now = new Date()): Promise<number> {
  const expired = await RoleAssignment.find({ source: "elevation", expiresAt: { $lte: now } }).lean();
  for (const a of expired) {
    await RoleAssignment.deleteOne({ _id: a._id });
    await recordEvent({ action: "authz.unassigned", stream: orgStream(String(a.organizationId)), actorId: null, subjectId: String(a.subjectId), data: { assignmentId: String(a._id), roleId: String(a.roleId), reason: "elevation expired", organizationId: String(a.organizationId) } });
  }
  return expired.length;
}
