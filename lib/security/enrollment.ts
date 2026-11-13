import { Types } from "mongoose";
import { getEnv } from "@/lib/config/env";
import { sendEmail } from "@/lib/email/email-service";
import { buildMfaEnrollmentEmail } from "@/lib/email/templates";
import { factorCount, factorCounts, mfaRequirement } from "@/lib/security/factors";
import { User } from "@/models/User";

/**
 * Getting a second step set up once a space requires one. Members who
 * already have one are simply asked for it. Those who don't get a grace
 * period: they're nudged (by email when it starts, and once per session on
 * the way to an app), and once it's over, apps won't let them in until they
 * set one up. Identity itself still lets them sign in, so they can.
 *
 * Apps that require a second step themselves don't wait: they need one now.
 */

export const MFA_GRACE_DAYS = 7;

export type EnrollmentState =
  | { state: "not_required" }
  | { state: "enrolled" }
  | { state: "grace"; until: string; daysLeft: number; spaces: string[] }
  | { state: "overdue"; since: string; spaces: string[] };

const DAY_MS = 86_400_000;

function graceEnd(now = Date.now()) {
  return new Date(now + MFA_GRACE_DAYS * DAY_MS);
}

/** Tells someone their grace period has started; never fails what started it. */
async function sendEnrollmentNotice(email: string, spaces: string[], until: Date) {
  try {
    const message = buildMfaEnrollmentEmail({ spaces, days: MFA_GRACE_DAYS, until: until.toDateString(), accountUrl: `${getEnv().APP_URL}/account/security#security-title` });
    await sendEmail({ to: email, subject: message.subject, text: message.text, html: message.html, meta: { kind: "mfa_enrollment" } });
  } catch (error) {
    console.error("Enrollment notice not sent:", error instanceof Error ? error.message : error);
  }
}

/** Starts the grace period for an account that needs one and hasn't got one going. Returns its end. */
async function startGrace(userId: Types.ObjectId, spaces: string[]): Promise<Date> {
  const until = graceEnd();
  // Only the first to get here starts it (and sends the email).
  const started = await User.findOneAndUpdate({ _id: userId, mfaGraceUntil: null }, { $set: { mfaGraceUntil: until } }, { new: true }).select("email mfaGraceUntil").lean();
  if (started) {
    await sendEnrollmentNotice(started.email, spaces, until);
    return until;
  }
  return (await User.findById(userId).select("mfaGraceUntil").lean())?.mfaGraceUntil ?? until;
}

/** Where an account stands; starts its grace period if a space requires a second step it doesn't have. */
export async function enrollmentState(userId: string | Types.ObjectId, now = Date.now()): Promise<EnrollmentState> {
  const id = new Types.ObjectId(String(userId));
  const requirement = await mfaRequirement(id);
  const spaces = requirement.sources.flatMap((s) => (s.type === "space" ? [s.name] : []));
  const settled = !spaces.length ? "not_required" : factorCount(await factorCounts(id)) > 0 ? "enrolled" : null;
  if (settled) {
    // A grace period that no longer applies is cleared, so a later requirement starts a fresh one.
    await User.updateOne({ _id: id, mfaGraceUntil: { $ne: null } }, { $set: { mfaGraceUntil: null } });
    return { state: settled };
  }
  const user = await User.findById(id).select("mfaGraceUntil").lean();
  const until = user?.mfaGraceUntil ?? (await startGrace(id, spaces));
  if (until.getTime() > now) return { state: "grace", until: until.toISOString(), daysLeft: Math.ceil((until.getTime() - now) / DAY_MS), spaces };
  return { state: "overdue", since: until.toISOString(), spaces };
}

/**
 * When a space starts requiring a second step: every member without one
 * begins a fresh grace period now (one left over from an earlier
 * requirement doesn't count), and is told.
 */
export async function startGraceForMembers(memberIds: Types.ObjectId[], spaceName: string) {
  for (const id of memberIds) {
    if (factorCount(await factorCounts(id)) > 0) continue;
    const until = graceEnd();
    const user = await User.findOneAndUpdate({ _id: id }, { $set: { mfaGraceUntil: until } }, { new: true }).select("email").lean();
    if (user) await sendEnrollmentNotice(user.email, [spaceName], until);
  }
}
