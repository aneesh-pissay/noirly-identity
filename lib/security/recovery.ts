import { AppError } from "@/lib/api/errors";
import { recordEvent, type RequestMeta } from "@/lib/audit/event-log";
import type { SignInMethod } from "@/lib/audit/chain";
import { getEnv } from "@/lib/config/env";
import { sendEmail } from "@/lib/email/email-service";
import { buildRecoveryCompletedEmail, buildRecoveryStartedEmail } from "@/lib/email/templates";
import { generateSecureToken, hashToken } from "@/lib/security/crypto";
import { createSession, revokeAllUserSessions } from "@/lib/sessions/session-service";
import { isSmsAvailable, sendSms } from "@/lib/sms/sms-service";
import { FactorRecovery } from "@/models/FactorRecovery";
import { Mfa, Passkey, SecurityChallenge } from "@/models/SecurityCredential";
import { User } from "@/models/User";
import { UserEmail } from "@/models/UserEmail";
import { hasRecoveryMethod, matchesRecoveryCode, sendRecoveryCode } from "@/lib/account/recovery-methods";
import { assessSignInRisk } from "@/lib/security/risk";
import { consumeRateLimit } from "@/lib/security/shared-rate-limit";
import { ADMIN_STREAM } from "@/lib/audit/chain";
import { buildNoticeEmail } from "@/lib/email/templates";
import { Types } from "mongoose";

/**
 * When the second step is lost (a broken phone, a lost key, no recovery
 * codes left). From the verification screen, someone who passed the first
 * step can ask to remove the account's second steps. Every verified address
 * (and a verified phone) is told at once, with a link to cancel; only after
 * RECOVERY_WAIT_HOURS, and after passing the first step again, can it be
 * finished. Someone who stole only the password has to get past the owner
 * not noticing for that long.
 */

export const RECOVERY_WAIT_HOURS = 24;
/** Without a verified recovery method to prove it, the wait is longer. */
export const RECOVERY_WAIT_HOURS_UNVERIFIED = 72;
/** A request not finished this long after it becomes available lapses. */
const RECOVERY_WINDOW_DAYS = 7;

export type RecoveryStatus =
  | { state: "none"; hasRecoveryMethod?: boolean }
  | { state: "waiting"; availableAt: string }
  | { state: "review"; availableAt: string }
  | { state: "ready"; availableAt: string };

/** The account behind a verification-screen challenge: the first step was passed. */
async function challengeOwner(challengeToken: string | null | undefined) {
  if (!challengeToken) throw new AppError("Verification expired. Sign in again.", 401, "invalid_challenge");
  const challenge = await SecurityChallenge.findOne({ tokenHash: hashToken(challengeToken), purpose: "login-mfa", expiresAt: { $gt: new Date() } }).lean();
  if (!challenge?.userId) throw new AppError("Verification expired. Sign in again.", 401, "invalid_challenge");
  return challenge;
}

async function liveRequest(userId: Types.ObjectId | null | undefined) {
  return FactorRecovery.findOne({ userId, status: "pending", expiresAt: { $gt: new Date() } }).sort({ createdAt: -1 }).lean();
}

export async function recoveryStatus(challengeToken: string | null | undefined): Promise<RecoveryStatus> {
  const challenge = await challengeOwner(challengeToken);
  const request = await liveRequest(challenge.userId);
  if (!request) return { state: "none", hasRecoveryMethod: await hasRecoveryMethod(challenge.userId) };
  const availableAt = request.availableAt.toISOString();
  if (request.review === "pending") return { state: "review", availableAt };
  return request.availableAt.getTime() <= Date.now() ? { state: "ready", availableAt } : { state: "waiting", availableAt };
}

/** Sends a code to the account's verified recovery methods, to prove it's the owner starting a recovery. */
export async function sendRecoveryProof(challengeToken: string | null | undefined) {
  const challenge = await challengeOwner(challengeToken);
  if (!(await hasRecoveryMethod(challenge.userId))) throw new AppError("This account has no recovery method to send a code to.", 400, "no_recovery_method");
  const limit = await consumeRateLimit(`recovery-proof:${String(challenge.userId)}`, 5, 3600);
  if (!limit.allowed) throw new AppError("Too many codes. Try again later.", 429, "rate_limited");
  const hash = await sendRecoveryCode(challenge.userId);
  await SecurityChallenge.updateOne({ _id: challenge._id }, { $set: { recoveryCodeHash: hash } });
}

/** Starts the wait, and tells the owner everywhere they can be reached. Asking again while one waits changes nothing. */
export async function startFactorRecovery(challengeToken: string | null | undefined, meta: RequestMeta & { deviceId?: string | null } = {}, code?: string): Promise<RecoveryStatus> {
  const challenge = await challengeOwner(challengeToken);
  if (await liveRequest(challenge.userId)) return recoveryStatus(challengeToken);
  const user = await User.findById(challenge.userId).select("email phoneNumber phoneVerifiedAt recoveryEmail recoveryEmailVerifiedAt").lean();
  if (!user) throw new AppError("Account unavailable", 401, "unauthorized");

  // With a recovery method, prove it (a code sent to it); then the wait is the shorter one.
  const hasMethod = await hasRecoveryMethod(user._id);
  if (hasMethod) {
    const fresh = await SecurityChallenge.findById(challenge._id).select("recoveryCodeHash").lean();
    if (!code || !matchesRecoveryCode(code, fresh?.recoveryCodeHash)) {
      throw new AppError("Enter the code we sent to your recovery address or phone.", 400, "recovery_code_required");
    }
  }
  // Started from somewhere risky: an admin reviews it before it can be finished.
  const risk = await assessSignInRisk(user._id, meta);
  const review = risk.level === "high" ? "pending" : "none";

  const cancelToken = generateSecureToken(32);
  const availableAt = new Date(Date.now() + (hasMethod ? RECOVERY_WAIT_HOURS : RECOVERY_WAIT_HOURS_UNVERIFIED) * 3_600_000);
  await FactorRecovery.create({ userId: user._id, availableAt, cancelTokenHash: hashToken(cancelToken), expiresAt: new Date(availableAt.getTime() + RECOVERY_WINDOW_DAYS * 86_400_000), verifiedByRecoveryMethod: hasMethod, review, reviewSignals: risk.signals });

  const cancelUrl = `${getEnv().APP_URL}/cancel-recovery?token=${encodeURIComponent(cancelToken)}`;
  const message = buildRecoveryStartedEmail({ availableAt: availableAt.toUTCString(), cancelUrl });
  // Every channel: each verified address, the recovery address, and the phone.
  const addresses = [
    user.email,
    ...(await UserEmail.find({ userId: user._id, verifiedAt: { $ne: null } }).lean()).map((e) => e.email),
    ...(user.recoveryEmail && user.recoveryEmailVerifiedAt ? [user.recoveryEmail] : []),
  ];
  for (const to of new Set(addresses)) {
    await sendEmail({ to, subject: message.subject, text: message.text, html: message.html, meta: { kind: "factor_recovery_started" } }).catch(() => undefined);
  }
  if (user.phoneNumber && user.phoneVerifiedAt && isSmsAvailable()) {
    await sendSms({ to: user.phoneNumber, body: "Noirly: someone asked to remove your second sign-in step. If it wasn't you, cancel it from the email we sent and change your password.", kind: "factor_recovery_started" }).catch(() => undefined);
  }
  await recordEvent({ action: "recovery.started", subjectId: user._id, request: meta, data: { availableAt: availableAt.toISOString(), verifiedByRecoveryMethod: hasMethod, review } });
  return review === "pending" ? { state: "review", availableAt: availableAt.toISOString() } : { state: "waiting", availableAt: availableAt.toISOString() };
}

/**
 * Finishes a request whose wait is over: removes the authenticator app,
 * recovery codes, passkeys and security keys, signs out everywhere else,
 * and signs in this browser with the first step it just passed.
 */
export async function finishFactorRecovery(challengeToken: string | null | undefined, meta: RequestMeta = {}) {
  const challenge = await challengeOwner(challengeToken);
  const request = await liveRequest(challenge.userId);
  if (!request) throw new AppError("There's no request to finish. Start one first.", 400, "no_recovery");
  if (request.review === "pending") throw new AppError("This request is being reviewed by our team first. We'll email you.", 400, "recovery_in_review");
  if (request.review === "denied") throw new AppError("This request was declined after review.", 400, "recovery_denied");
  if (request.availableAt.getTime() > Date.now()) throw new AppError(`This can be finished after ${request.availableAt.toUTCString()}.`, 400, "recovery_waiting");
  const claimed = await FactorRecovery.updateOne({ _id: request._id, status: "pending" }, { $set: { status: "completed" } });
  if (claimed.modifiedCount !== 1) throw new AppError("This request was already finished or cancelled", 409, "recovery_done");
  await SecurityChallenge.deleteOne({ _id: challenge._id });

  const userId = challenge.userId!;
  await Promise.all([Mfa.deleteMany({ userId }), Passkey.deleteMany({ userId })]);
  // The account's own requirement goes too, or it couldn't sign in; a space's requirement starts its grace period again.
  await User.updateOne({ _id: userId }, { $set: { mfaRequired: false, mfaGraceUntil: null, lastLoginAt: new Date() } });
  await revokeAllUserSessions(userId);
  const method = (challenge.method as SignInMethod | null) ?? "password";
  const session = await createSession({ userId, ipAddress: meta.ipAddress, userAgent: meta.userAgent, place: meta.place, methods: [method] });
  await recordEvent({ action: "recovery.completed", subjectId: userId, request: meta, data: { otherSessionsSignedOut: true } });

  const user = await User.findById(userId).select("email").lean();
  if (user) {
    const notice = buildRecoveryCompletedEmail();
    await sendEmail({ to: user.email, subject: notice.subject, text: notice.text, html: notice.html, meta: { kind: "factor_recovery_completed" } }).catch(() => undefined);
  }
  return { sessionToken: session.token };
}

/** "This wasn't me", from the emailed link. */
export async function cancelFactorRecovery(token: string, meta: RequestMeta = {}) {
  const request = token.length >= 20 ? await FactorRecovery.findOne({ cancelTokenHash: hashToken(token) }).lean() : null;
  if (!request) throw new AppError("This link is invalid", 400, "invalid_token");
  if (request.status !== "pending") throw new AppError(request.status === "cancelled" ? "This request was already cancelled" : "This request was already finished. Reset your password and check your security activity.", 409, "recovery_done");
  await FactorRecovery.updateOne({ _id: request._id, status: "pending" }, { $set: { status: "cancelled" } });
  await recordEvent({ action: "recovery.cancelled", subjectId: request.userId, actorId: null, request: meta });
}

/** Admin: recoveries waiting for review, oldest first. */
export async function listRecoveryReviews() {
  const pending = await FactorRecovery.find({ status: "pending", review: "pending" }).sort({ createdAt: 1 }).limit(100).lean();
  const users = new Map((await User.find({ _id: { $in: pending.map((p) => p.userId) } }).select("email").lean()).map((u) => [String(u._id), u.email]));
  return pending.map((p) => ({
    id: String(p._id),
    email: users.get(String(p.userId)) ?? "(deleted)",
    startedAt: p.createdAt.toISOString(),
    availableAt: p.availableAt.toISOString(),
    signals: p.reviewSignals ?? [],
    verifiedByRecoveryMethod: Boolean(p.verifiedByRecoveryMethod),
  }));
}

/** Admin: lets a reviewed recovery go on (still after its wait), or declines it. The owner hears either way. */
export async function decideRecoveryReview(adminId: string, recoveryId: string, approve: boolean, meta: RequestMeta = {}) {
  if (!Types.ObjectId.isValid(recoveryId)) throw new AppError("Not found", 404, "not_found");
  const request = await FactorRecovery.findOneAndUpdate(
    { _id: new Types.ObjectId(recoveryId), status: "pending", review: "pending" },
    { $set: { review: approve ? "approved" : "denied", reviewedBy: new Types.ObjectId(adminId), ...(approve ? {} : { status: "cancelled" }) } },
    { returnDocument: "after" },
  ).lean();
  if (!request) throw new AppError("Nothing to review there", 404, "not_found");
  await recordEvent({ action: approve ? "recovery.review_approved" : "recovery.review_denied", stream: ADMIN_STREAM, actorId: adminId, subjectId: String(request.userId), request: meta, data: { recoveryId } });
  await recordEvent({ action: approve ? "recovery.review_approved" : "recovery.review_denied", subjectId: String(request.userId), actorId: adminId, request: meta });
  const user = await User.findById(request.userId).select("email").lean();
  if (user) {
    await sendEmail({
      to: user.email,
      ...buildNoticeEmail({
        subject: approve ? "Your account recovery can go on" : "Your account recovery was declined",
        paragraphs: [approve ? `It can be finished after ${request.availableAt.toUTCString()}, by signing in again.` : "After review, the request to remove your second step was declined. If that was you, contact support."],
      }),
      meta: { kind: "recovery-review" },
    }).catch(() => undefined);
  }
}
