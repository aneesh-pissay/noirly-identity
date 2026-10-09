import type { Types } from "mongoose";
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
  await Promise.all([
    Session.deleteMany({ userId }),
    AccessToken.deleteMany({ userId }),
    RefreshToken.deleteMany({ userId }),
    AuthorizationCode.deleteMany({ userId }),
    EmailVerificationToken.deleteMany({ userId }),
    PasswordResetToken.deleteMany({ userId }),
    LinkedAccount.deleteMany({ userId }),
    OrganizationMembership.deleteMany({ userId }),
  ]);
  await User.deleteOne({ _id: userId });
  return { deleted: true, ...(await notifyAccountDeleted(sub)) };
}

async function loadUser(userId: Types.ObjectId | string): Promise<UserDocument> {
  const user = await User.findById(userId).select("+passwordHash");
  if (!user || user.status === "disabled") {
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
