import { Types } from "mongoose";
import { hasRecoveryMethod } from "@/lib/account/recovery-methods";
import { factorCounts, mfaRequirement } from "@/lib/security/factors";
import { AppAccess } from "@/models/AppAccess";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { Session } from "@/models/Session";
import { User } from "@/models/User";

/**
 * The account home page's summary: a short security checkup (what's worth
 * fixing, most important first) and a count for each area, so people can
 * see at a glance whether their account is in good shape.
 */

export type CheckupItem = {
  id: "password-breached" | "email-unverified" | "second-step" | "second-step-required" | "recovery";
  /** What's wrong, in a few words. */
  title: string;
  /** Why it matters and what to do. */
  detail: string;
  /** Where it's fixed. */
  href: string;
  severity: "high" | "medium";
};

export type AccountOverview = {
  checkup: CheckupItem[];
  secondStep: { on: boolean; authenticator: boolean; keys: number };
  recovery: boolean;
  devices: number;
  apps: number;
  spaces: number;
};

export async function accountOverview(userIdInput: string): Promise<AccountOverview> {
  const userId = new Types.ObjectId(userIdInput);
  const [user, factors, recovery, requirement, devices, apps, spaces] = await Promise.all([
    User.findById(userId).select("emailVerified passwordBreachedAt passwordHash").lean<{ emailVerified?: boolean; passwordBreachedAt?: Date | null; passwordHash?: string | null }>(),
    factorCounts(userId),
    hasRecoveryMethod(userId),
    mfaRequirement(userId),
    Session.countDocuments({ userId, revokedAt: null, expiresAt: { $gt: new Date() } }),
    AppAccess.countDocuments({ userId, removedAt: null }),
    OrganizationMembership.countDocuments({ userId }),
  ]);
  const secondStep = factors.totp || factors.keys > 0;
  const checkup: CheckupItem[] = [];
  if (user?.passwordBreachedAt) {
    checkup.push({ id: "password-breached", severity: "high", title: "Your password was found in a data breach", detail: "It appeared in a leak from another site. Change it now, so nobody can use it to get in.", href: "/account/security#password" });
  }
  if (user && !user.emailVerified) {
    checkup.push({ id: "email-unverified", severity: "high", title: "Your email address isn't confirmed", detail: "Open the link we sent you. Until then, sign-in links and security alerts can't reach you.", href: "/account/profile#emails-title" });
  }
  if (!secondStep) {
    const required = requirement.required && requirement.sources.some((s) => s.type === "space");
    checkup.push(required
      ? { id: "second-step-required", severity: "high", title: "A space you're in requires a second step", detail: "Set up an authenticator app or a passkey, or you won't be able to open its apps.", href: "/account/security#security-title" }
      : { id: "second-step", severity: "medium", title: "Add a second step", detail: "With an authenticator app or a passkey, a stolen password isn't enough to get into your account.", href: "/account/security#security-title" });
  }
  if (!recovery) {
    checkup.push({ id: "recovery", severity: "medium", title: "Add a recovery address", detail: "If you ever lose your second step, a code sent there gets you back in sooner.", href: "/account/security#recovery-methods-title" });
  }
  return { checkup, secondStep: { on: secondStep, authenticator: factors.totp, keys: factors.keys }, recovery, devices, apps, spaces };
}
