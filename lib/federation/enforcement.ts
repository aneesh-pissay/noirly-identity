import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { orgStream } from "@/lib/audit/chain";
import { recordEvent } from "@/lib/audit/event-log";
import { getEnv } from "@/lib/config/env";
import { sendEmail } from "@/lib/email/email-service";
import { buildNoticeEmail } from "@/lib/email/templates";
import { actorLabel, noticeToSpaceOwners, noticeToUser, spaceName } from "@/lib/notifications/notices";
import { revokeNonSsoSessions } from "@/lib/sessions/session-service";
import { requireDomainOwner } from "@/lib/spaces/domains";
import { IdentityProvider } from "@/models/IdentityProvider";
import { Organization } from "@/models/Organization";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { Mfa, Passkey } from "@/models/SecurityCredential";
import { User } from "@/models/User";

/**
 * Domain-based SSO enforcement: once an organization turns it on, anyone
 * whose address is at one of its IdPs' domains signs in through that IdP and
 * no other way (checked in createSession, so every sign-in path is covered).
 *
 * Break-glass: up to three named accounts may still sign in another way when
 * the IdP is down, but only with a second step (authenticator, passkey or a
 * recovery code); every such sign-in is recorded and emailed to the owners.
 */

const MAX_BREAK_GLASS = 3;
const SECOND_STEPS = new Set(["totp", "passkey", "recovery_code"]);

export type SsoEnforcement = { enforced: boolean; breakGlass: Array<{ userId: string; email: string }> };

async function view(spaceId: Types.ObjectId): Promise<SsoEnforcement> {
  const org = await Organization.findById(spaceId).select("ssoEnforced breakGlassUserIds").lean<{ ssoEnforced?: boolean; breakGlassUserIds?: Types.ObjectId[] }>();
  const users = await User.find({ _id: { $in: org?.breakGlassUserIds ?? [] } }).select("email").lean();
  return { enforced: Boolean(org?.ssoEnforced), breakGlass: users.map((u) => ({ userId: String(u._id), email: u.email })) };
}

export async function getSsoEnforcement(actorId: string, spaceId: string) {
  await requireDomainOwner(spaceId, actorId);
  return view(new Types.ObjectId(spaceId));
}

export async function setSsoEnforcement(actorId: string, spaceId: string, input: { enforced?: boolean; breakGlassEmails?: string[] }): Promise<SsoEnforcement> {
  await requireDomainOwner(spaceId, actorId);
  const space = new Types.ObjectId(spaceId);
  const set: Record<string, unknown> = {};
  if (input.breakGlassEmails) {
    const emails = [...new Set(input.breakGlassEmails.map((e) => e.trim().toLowerCase()).filter(Boolean))];
    if (emails.length > MAX_BREAK_GLASS) throw new AppError(`Up to ${MAX_BREAK_GLASS} break-glass accounts`, 400, "invalid_request");
    const users = await User.find({ email: { $in: emails } }).select("_id email").lean();
    const ids = users.map((u) => u._id);
    const members = await OrganizationMembership.countDocuments({ organizationId: space, userId: { $in: ids } });
    if (users.length !== emails.length || members !== ids.length) throw new AppError("Break-glass accounts must be members of this space", 400, "invalid_request");
    const [mfa, passkeys] = await Promise.all([Mfa.distinct("userId", { userId: { $in: ids }, enabled: true }), Passkey.distinct("userId", { userId: { $in: ids } })]);
    const covered = new Set([...mfa, ...passkeys].map(String));
    const without = users.filter((u) => !covered.has(String(u._id)));
    if (without.length) throw new AppError(`Break-glass accounts need a second step first: ${without.map((u) => u.email).join(", ")}`, 400, "second_step_required");
    set.breakGlassUserIds = ids;
  }
  if (input.enforced !== undefined) {
    if (input.enforced && !(await IdentityProvider.exists({ organizationId: space, enabled: true }))) throw new AppError("Set up an identity provider first", 400, "no_provider");
    set.ssoEnforced = input.enforced;
  }
  await Organization.updateOne({ _id: space }, { $set: set });
  const result = await view(space);
  if (input.enforced !== undefined || input.breakGlassEmails) {
    const what = input.enforced === undefined ? "changed its break-glass accounts" : input.enforced ? "now requires single sign-on" : "no longer requires single sign-on";
    await noticeToSpaceOwners(spaceId, {
      kind: "sso-changed",
      subject: `${await spaceName(spaceId)} ${what}`,
      paragraphs: [
        `${await actorLabel(actorId)} changed the space's single sign-on rules: it ${what}.`,
        result.breakGlass.length ? `Break-glass accounts: ${result.breakGlass.map((b) => b.email).join(", ")}.` : "There are no break-glass accounts: if the identity provider is down, nobody at these domains can sign in.",
      ],
      action: { label: "Review single sign-on", path: "/spaces" },
    });
  }
  await recordEvent({ action: "sso.enforcement_changed", stream: orgStream(spaceId), actorId, subjectId: null, data: { organizationId: spaceId, enforced: result.enforced, breakGlass: result.breakGlass.map((b) => b.userId) } });
  if (input.enforced) await signOutUnenforcedSessions(space, new Set(result.breakGlass.map((b) => b.userId)), spaceId);
  return result;
}

/** Turning enforcement on ends members' sessions that didn't come through the IdP (break-glass accounts keep theirs). */
async function signOutUnenforcedSessions(space: Types.ObjectId, keep: Set<string>, spaceId: string) {
  const domains = (await IdentityProvider.find({ organizationId: space, enabled: true }).select("domains").lean()).flatMap((p) => p.domains);
  if (!domains.length) return;
  const pattern = new RegExp(`@(${domains.map((d) => d.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})$`, "i");
  const users = await User.find({ email: pattern }).select("_id").lean();
  const ids = users.map((u) => u._id).filter((id) => !keep.has(String(id)));
  // Tokens revoked and apps told, as for any sign-out; then each person hears why.
  const signedOut = await revokeNonSsoSessions(ids);
  const name = await spaceName(spaceId);
  for (const userId of signedOut) {
    await noticeToUser(userId, {
      kind: "sso-required",
      subject: `Sign in through ${name}'s single sign-on`,
      paragraphs: [`${name} now requires its own sign-in for your address, so you were signed out of Noirly where you'd signed in another way. Next time, type your address on the sign-in page and you'll be sent to your organization's sign-in.`],
      action: { label: "Sign in", path: "/login" },
    });
  }
}

/** The enforced provider for an address, if its domain's organization requires SSO. */
export async function enforcedProviderFor(email: string) {
  const domain = email.split("@")[1]?.toLowerCase();
  if (!domain) return null;
  const idp = await IdentityProvider.findOne({ domains: domain, enabled: true }).select("organizationId name").lean();
  if (!idp) return null;
  const org = await Organization.findById(idp.organizationId).select("ssoEnforced breakGlassUserIds name status").lean<{ ssoEnforced?: boolean; breakGlassUserIds?: Types.ObjectId[]; name: string; status: string }>();
  if (!org?.ssoEnforced || org.status !== "active") return null;
  return { idpId: String(idp._id), idpName: idp.name, organizationId: String(idp.organizationId), organizationName: org.name, breakGlass: (org.breakGlassUserIds ?? []).map(String) };
}

/**
 * Called for every sign-in (createSession with methods): refuses a non-SSO
 * sign-in to an enforced domain, unless it's a break-glass account with a
 * second step, which is let in, recorded and reported.
 */
export async function assertSsoAllowed(userId: string, methods: readonly string[], meta: { ipAddress?: string | null; userAgent?: string | null; place?: string | null } = {}) {
  if (methods.includes("sso")) return;
  const user = await User.findById(userId).select("email").lean();
  if (!user) return;
  const enforced = await enforcedProviderFor(user.email);
  if (!enforced) return;
  if (!enforced.breakGlass.includes(userId) || !methods.some((m) => SECOND_STEPS.has(m))) {
    throw new AppError(`${enforced.organizationName} signs you in through ${enforced.idpName}. Use "Sign in with your organization".`, 403, "sso_required");
  }
  await recordEvent({ action: "sso.break_glass_used", stream: orgStream(enforced.organizationId), actorId: userId, subjectId: userId, request: meta, data: { organizationId: enforced.organizationId, methods } });
  const owners = await OrganizationMembership.find({ organizationId: new Types.ObjectId(enforced.organizationId), role: "owner" }).select("userId").lean();
  const recipients = await User.find({ _id: { $in: owners.map((o) => o.userId) } }).select("email").lean();
  await Promise.all(
    recipients.map((r) =>
      sendEmail({
        to: r.email,
        ...buildNoticeEmail({
          subject: `Break-glass sign-in to ${enforced.organizationName}`,
          paragraphs: [`${user.email} signed in without ${enforced.idpName}, using a break-glass account${meta.place ? `, from ${meta.place}` : ""}. If your identity provider isn't down, check this sign-in now.`],
          action: { label: "Review activity", url: new URL("/spaces", getEnv().APP_URL).toString() },
        }),
        meta: { kind: "break-glass" },
      }).catch(() => undefined),
    ),
  );
}
