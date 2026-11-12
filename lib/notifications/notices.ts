import { Types } from "mongoose";
import { getEnv } from "@/lib/config/env";
import { sendEmail } from "@/lib/email/email-service";
import { buildNoticeEmail } from "@/lib/email/templates";
import { Organization } from "@/models/Organization";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { User } from "@/models/User";

/**
 * Plain notice emails for things people should hear about but that don't
 * need them to act at once: changes to how a space signs people in, accounts
 * an organization made or locked, and deliveries that gave up. They never
 * throw: the change they report has already happened.
 *
 * Each says who it's for and what to do if it's unexpected; none carries a
 * secret or a sign-in link.
 */

export type Notice = { subject: string; paragraphs: string[]; action?: { label: string; path: string }; kind: string };

const url = (path: string) => new URL(path, getEnv().APP_URL).toString();

async function deliver(to: string[], notice: Notice) {
  const email = buildNoticeEmail({ subject: notice.subject, paragraphs: notice.paragraphs, ...(notice.action ? { action: { label: notice.action.label, url: url(notice.action.path) } } : {}) });
  await Promise.all([...new Set(to)].map((address) => sendEmail({ to: address, ...email, meta: { kind: notice.kind } }).catch(() => undefined)));
}

/** One account, at its primary address. */
export async function noticeToUser(userId: string | Types.ObjectId, notice: Notice) {
  try {
    const user = await User.findById(userId).select("email").lean();
    if (user) await deliver([user.email], notice);
  } catch (error) {
    console.error("Notice to user failed", error instanceof Error ? error.message : error);
  }
}

/** The space's name, for wording. */
export async function spaceName(spaceId: string | Types.ObjectId) {
  return (await Organization.findById(spaceId).select("name").lean())?.name ?? "your space";
}

/**
 * Those responsible for how a space signs people in: its owners, and admins
 * given the domains area.
 */
export async function noticeToSpaceOwners(spaceId: string | Types.ObjectId, notice: Notice) {
  try {
    const members = await OrganizationMembership.find({ organizationId: new Types.ObjectId(String(spaceId)), $or: [{ role: "owner" }, { role: "admin", adminAreas: "domains" }] }).select("userId").lean();
    const users = await User.find({ _id: { $in: members.map((m) => m.userId) } }).select("email").lean();
    await deliver(users.map((u) => u.email), notice);
  } catch (error) {
    console.error("Notice to space owners failed", error instanceof Error ? error.message : error);
  }
}

/** Identity's own admins. */
export async function noticeToAdmins(notice: Notice) {
  try {
    const admins = await User.find({ roles: "admin" }).select("email").lean();
    await deliver(admins.map((u) => u.email), notice);
  } catch (error) {
    console.error("Notice to admins failed", error instanceof Error ? error.message : error);
  }
}

/** Who did it, for wording ("Ada Lovelace (ada@acme.com)"), or "the directory" for SCIM. */
export async function actorLabel(actorId: string | null | undefined) {
  if (!actorId) return "your organization's directory";
  const user = await User.findById(actorId).select("displayName email").lean();
  return user ? `${user.displayName} (${user.email})` : "someone in the space";
}
