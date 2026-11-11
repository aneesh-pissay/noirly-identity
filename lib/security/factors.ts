import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { Mfa, Passkey } from "@/models/SecurityCredential";
import { User } from "@/models/User";
import { Organization } from "@/models/Organization";
import { OrganizationMembership } from "@/models/OrganizationMembership";

/**
 * Second factors: the authenticator app, and passkeys and security keys
 * (any of them, including second-step-only keys). While an account requires
 * a second step at sign-in, its last factor can't be removed, or the next
 * sign-in would have nothing to ask for.
 */

export type FactorCounts = { totp: boolean; keys: number };

export function factorCount(counts: FactorCounts) {
  return (counts.totp ? 1 : 0) + counts.keys;
}

export async function factorCounts(userId: string | Types.ObjectId): Promise<FactorCounts> {
  const [totp, keys] = await Promise.all([Mfa.exists({ userId, enabled: true }), Passkey.countDocuments({ userId })]);
  return { totp: Boolean(totp), keys };
}

/** Why an account must use a second step: its own setting, or a space it's in. (Apps that require one ask at sign-in.) */
export type MfaSource = { type: "account" } | { type: "space"; id: string; name: string };

export async function mfaRequirement(userId: string | Types.ObjectId): Promise<{ required: boolean; sources: MfaSource[] }> {
  const id = new Types.ObjectId(String(userId));
  const [user, memberships] = await Promise.all([
    User.findById(id).select("mfaRequired").lean(),
    OrganizationMembership.find({ userId: id }).select("organizationId").lean(),
  ]);
  const spaces = memberships.length
    ? await Organization.find({ _id: { $in: memberships.map((m) => m.organizationId) }, status: "active", requireMfa: true }).select("name").sort({ name: 1 }).lean()
    : [];
  const sources: MfaSource[] = [
    ...(user?.mfaRequired ? [{ type: "account" as const }] : []),
    ...spaces.map((space) => ({ type: "space" as const, id: String(space._id), name: space.name })),
  ];
  return { required: sources.length > 0, sources };
}

/** Whether every sign-in must include a second step. */
export async function isMfaRequired(userId: string | Types.ObjectId): Promise<boolean> {
  return (await mfaRequirement(userId)).required;
}

/** Turns the account's own requirement on (it must have a second step already) or off. */
export async function setAccountMfaRequired(userId: string, required: boolean) {
  if (required && factorCount(await factorCounts(userId)) === 0) {
    throw new AppError("Set up an authenticator app, passkey or security key first.", 400, "no_second_factor");
  }
  await User.updateOne({ _id: new Types.ObjectId(userId) }, { $set: { mfaRequired: required } });
}

/** Refuses a removal that would leave a required second step with nothing to use. */
export async function assertKeepsSecondFactor(userId: string, removing: { totp?: boolean; keys?: number }) {
  if (!(await isMfaRequired(userId))) return;
  const counts = await factorCounts(userId);
  const after = factorCount({ totp: counts.totp && !removing.totp, keys: counts.keys - (removing.keys ?? 0) });
  if (after < 1) {
    throw new AppError("A second step is required at sign-in for your account, so keep at least one: add another passkey, security key or authenticator app first.", 409, "last_second_factor");
  }
}
