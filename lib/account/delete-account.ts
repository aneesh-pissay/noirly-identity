import { isBlockedUser } from "@/lib/auth/user-policy";
import { Mfa, Passkey, SecurityChallenge } from "@/models/SecurityCredential";
import { MobileBrowserLogin } from "@/models/MobileBrowserLogin";
import { Types } from "mongoose";
import { handOverOwnedSpaces, spaceIdsForUser } from "@/lib/spaces/space-service";
import { notifySpaceChanged } from "@/lib/spaces/space-webhooks";
import { AppError } from "@/lib/api/errors";
import { notifyAccountDeleted } from "@/lib/account/deletion-webhooks";
import { verifyPassword } from "@/lib/security/password";
import { validateSession } from "@/lib/sessions/session-service";
import { resolveAccessToken } from "@/lib/tokens/token-service";
import { AccessToken } from "@/models/AccessToken";
import { AuthorizationCode } from "@/models/AuthorizationCode";
import { EmailVerificationToken } from "@/models/EmailVerificationToken";
import { LinkedAccount } from "@/models/LinkedAccount";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { PasswordResetToken } from "@/models/PasswordResetToken";
import { RefreshToken } from "@/models/RefreshToken";
import { Session } from "@/models/Session";
import { User, type UserDocument } from "@/models/User";
import { UserEmail } from "@/models/UserEmail";
import { EmailChangeUndo } from "@/models/EmailChangeUndo";
import { Avatar } from "@/models/Avatar";
import { AppAccess } from "@/models/AppAccess";
import { AccountMerge } from "@/models/AccountMerge";
import { MagicLink } from "@/models/MagicLink";
import { PhoneVerification } from "@/models/PhoneVerification";
import { FactorRecovery } from "@/models/FactorRecovery";
import { purgeUserEvents, recordEvent } from "@/lib/audit/event-log";
import { SYSTEM_STREAM } from "@/lib/audit/chain";

/**
 * Deleting a Noirly account.
 *
 * The account and everything Identity holds for it (sessions, tokens, Google
 * link, organization memberships, email tokens) are removed at once, not
 * soft-deleted. Product apps are then told through the deletion webhooks so
 * they remove their own data. Every way in re-checks who is asking: the
 * password for accounts that have one, else the account's email typed out.
 */

export type DeletionProof = {
  password?: string;
  /** For Google-only accounts (no password): the account email, typed. */
  confirmEmail?: string;
  /** Only check the proof; delete nothing. */
  verifyOnly?: boolean;
};

export type DeletionResult = { deleted: boolean; delivered: string[]; pending: string[] };

async function checkProof(user: UserDocument, proof: DeletionProof): Promise<void> {
  if (user.passwordHash) {
    const ok = Boolean(proof.password) && (await verifyPassword(user.passwordHash, proof.password!));
    if (!ok) throw new AppError("Password is incorrect", 400, "invalid_password");
    return;
  }
  if ((proof.confirmEmail ?? "").trim().toLowerCase() !== user.email) {
    throw new AppError("Type your account email exactly to confirm", 400, "confirmation_mismatch");
  }
}

/** Removes the account and every Identity record tied to it, then notifies apps. */
export async function deleteUserAccount(
  userId: Types.ObjectId | string,
): Promise<DeletionResult> {
  const sub = String(userId);
  // Spaces they're in lose a member; spaces they alone own pass to someone else.
  const userOid = new Types.ObjectId(sub);
  const spaceIds = await spaceIdsForUser(userOid);
  await handOverOwnedSpaces(userOid);
  // Apps that know them hear it while that can still be worked out (it's in AppAccess, about to go).
  const { emitLifecycle } = await import("@/lib/webhooks/lifecycle");
  await emitLifecycle("user.deleted", { userId: sub });
  await Promise.all([
    Mfa.deleteMany({ userId }),
    Passkey.deleteMany({ userId }),
    SecurityChallenge.deleteMany({ userId }),
    MobileBrowserLogin.deleteMany({ userId }),
    Session.deleteMany({ userId }),
    AccessToken.deleteMany({ userId }),
    RefreshToken.deleteMany({ userId }),
    AuthorizationCode.deleteMany({ userId }),
    EmailVerificationToken.deleteMany({ userId }),
    PasswordResetToken.deleteMany({ userId }),
    LinkedAccount.deleteMany({ userId }),
    UserEmail.deleteMany({ userId }),
    EmailChangeUndo.deleteMany({ userId }),
    Avatar.deleteMany({ userId }),
    AppAccess.deleteMany({ userId }),
    MagicLink.deleteMany({ userId }),
    PhoneVerification.deleteMany({ userId }),
    FactorRecovery.deleteMany({ userId }),
    AccountMerge.deleteMany({ $or: [{ keeperId: userId }, { sourceId: userId }] }),
    OrganizationMembership.deleteMany({ userId }),
  ]);
  await User.deleteOne({ _id: userId });
  // The account's own history goes with it; that it was deleted (by id only) is kept.
  await purgeUserEvents(sub);
  // No address or device: what's left of a deleted account is that it existed and went.
  await recordEvent({ action: "account.deleted", stream: SYSTEM_STREAM, subjectId: sub, data: { spaces: spaceIds.length } });
  await notifySpaceChanged(spaceIds);
  return { deleted: true, ...(await notifyAccountDeleted(sub)) };
}

async function loadUser(userId: Types.ObjectId | string): Promise<UserDocument> {
  const user = await User.findById(userId).select("+passwordHash");
  if (!user || isBlockedUser(user)) {
    throw new AppError("Authentication required", 401, "unauthorized");
  }
  return user;
}

/** Web: the signed-in browser session deletes its own account. */
export async function deleteAccountForSession(sessionToken: string | null, proof: DeletionProof) {
  const ctx = await validateSession(sessionToken);
  if (!ctx) throw new AppError("Authentication required", 401, "unauthorized");
  const user = await loadUser(ctx.userId);
  await checkProof(user, proof);
  return proof.verifyOnly ? { deleted: false, delivered: [], pending: [] } : deleteUserAccount(user._id);
}

/** Mobile: an app's access token (`Authorization: Bearer`) deletes its own account. */
export async function deleteAccountForAccessToken(accessToken: string | null, proof: DeletionProof) {
  const token = accessToken ? await resolveAccessToken(accessToken) : null;
  if (!token) throw new AppError("Access token is invalid or expired", 401, "invalid_token");
  const user = await loadUser(token.userId);
  await checkProof(user, proof);
  return proof.verifyOnly ? { deleted: false, delivered: [], pending: [] } : deleteUserAccount(user._id);
}
