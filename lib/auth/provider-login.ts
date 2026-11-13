import { isBlockedUser } from "@/lib/auth/user-policy";
import { requireSecondFactor, type MobileMfaContext } from "@/lib/security/mfa";
import { assessSignInRisk } from "@/lib/security/risk";
import { AppError } from "@/lib/api/errors";
import { toPublicUser } from "@/lib/auth/user-mapper";
import { createSession, revokeAllUserSessions } from "@/lib/sessions/session-service";
import { AccessToken } from "@/models/AccessToken";
import { AuthorizationCode } from "@/models/AuthorizationCode";
import { LinkedAccount } from "@/models/LinkedAccount";
import { MobileBrowserLogin } from "@/models/MobileBrowserLogin";
import { PasswordResetToken } from "@/models/PasswordResetToken";
import { RefreshToken } from "@/models/RefreshToken";
import { Mfa, Passkey, SecurityChallenge } from "@/models/SecurityCredential";
import { User, type UserDocument } from "@/models/User";
import { UserEmail } from "@/models/UserEmail";
import { recordEvent } from "@/lib/audit/event-log";
import { PROVIDER_LABEL, type Provider } from "@/lib/account/sign-in-methods";
import type { PublicUser } from "@/types";

/**
 * Signing in with another identity provider (Google, Apple), the same way
 * for each: the provider's own id for the person finds a linked account;
 * failing that, an address the provider has verified finds the account that
 * owns it (and links it); failing that, a new account is made.
 */

export type ProviderProfile = {
  sub: string;
  email: string;
  emailVerified: boolean;
  firstName: string;
  lastName: string;
  displayName: string;
  avatarUrl: string | null;
};

export type ProviderLoginMeta = { ipAddress?: string | null; userAgent?: string | null; place?: string | null; deviceId?: string | null; mobileMfa?: MobileMfaContext };

const LABEL = PROVIDER_LABEL;

/**
 * Clears every way into an account that came from its unverified registrant:
 * password, authenticator, passkeys, other linked logins, sessions and tokens.
 */
export async function discardUnverifiedRegistration(user: Pick<UserDocument, "_id" | "passwordHash">) {
  // In memory too: the caller saves this document again below.
  user.passwordHash = null;
  await Promise.all([
    User.updateOne({ _id: user._id }, { $set: { passwordHash: null } }),
    Mfa.deleteMany({ userId: user._id }),
    Passkey.deleteMany({ userId: user._id }),
    SecurityChallenge.deleteMany({ userId: user._id }),
    LinkedAccount.deleteMany({ userId: user._id }),
    UserEmail.deleteMany({ userId: user._id }),
    PasswordResetToken.updateMany({ userId: user._id, usedAt: null }, { $set: { usedAt: new Date() } }),
    MobileBrowserLogin.deleteMany({ userId: user._id }),
    AccessToken.updateMany({ userId: user._id, revokedAt: null }, { $set: { revokedAt: new Date() } }),
    RefreshToken.updateMany({ userId: user._id, revokedAt: null }, { $set: { revokedAt: new Date() } }),
    AuthorizationCode.deleteMany({ userId: user._id }),
    revokeAllUserSessions(user._id),
  ]);
}

/**
 * Google, Apple, Microsoft and GitHub never sign anyone in to Noirly or create
 * an account: people sign in with their email (password, link or code) or a
 * passkey, and may link provider accounts from Security. Every provider
 * sign-in (web, One Tap and the mobile apps) comes through here.
 */
export const PROVIDER_SIGN_IN_ENABLED: boolean = false;

/** The sign-in page, saying why, for a provider start that isn't linking (an old button or bookmark). */
export function providerSignInOffUrl(provider: Provider, appUrl: string) {
  const url = new URL("/login", appUrl);
  url.searchParams.set("error", `Noirly doesn't sign in with ${LABEL[provider]}. Sign in with your email address or a passkey.`);
  return url;
}

export async function loginWithProviderProfile(provider: Provider, profile: ProviderProfile, meta: ProviderLoginMeta): Promise<{ user: PublicUser; sessionToken: string }> {
  if (!PROVIDER_SIGN_IN_ENABLED) {
    throw new AppError(
      `Noirly doesn't sign in with ${LABEL[provider]}. Sign in with your email address or a passkey; you can still link ${LABEL[provider]} under Account, then Security.`,
      403,
      "provider_sign_in_off",
    );
  }
  const linked = await LinkedAccount.findOne({ provider, providerAccountId: profile.sub });

  let user = linked ? await User.findById(linked.userId).select("+passwordHash") : null;

  // Without a link, the email is all there is to go on, so it must be one the provider proved.
  if (!user && !profile.emailVerified) {
    throw new AppError(
      `${LABEL[provider]} couldn't confirm your email address, so it can't be used to find or create a Noirly account. Sign in another way, then link ${LABEL[provider]} from your account page.`,
      400,
      `${provider}_email_unverified`,
    );
  }

  if (!user) {
    user = await User.findOne({ email: profile.email }).select("+passwordHash");
    if (!user) {
      // The provider proves the address; if an account confirmed it as an additional one, it's that account.
      const additional = await UserEmail.findOne({ email: profile.email, verifiedAt: { $ne: null } }).lean();
      if (additional) user = await User.findById(additional.userId).select("+passwordHash");
    }
    if (user) {
      if (isBlockedUser(user)) {
        throw new AppError("Unable to sign in", 401, "invalid_credentials");
      }
      const unverified = !user.emailVerified;
      if (unverified) {
        // Nobody ever proved they own this address, so anyone could have
        // registered it first. The provider now proves the owner: drop whatever
        // the earlier registrant set up, or they keep a way into this account.
        await discardUnverifiedRegistration(user);
      }
      // One link per provider: an account already linked to another of this provider's accounts isn't relinked.
      if (await LinkedAccount.exists({ userId: user._id, provider })) {
        throw new AppError(`This email's Noirly account is linked to a different ${LABEL[provider]} account. Sign in with that one, or another way.`, 409, "linked_elsewhere");
      }
      await LinkedAccount.create({ userId: user._id, provider, providerAccountId: profile.sub, email: profile.email });
      await recordEvent({ action: "account.identity_linked", subjectId: user._id, clientId: meta.mobileMfa?.clientId, request: meta, data: { provider, email: profile.email, discardedUnverifiedRegistration: unverified } });
    }
  }

  if (!user) {
    user = await User.create({
      email: profile.email,
      passwordHash: null,
      firstName: profile.firstName,
      lastName: profile.lastName,
      displayName: profile.displayName,
      avatarUrl: profile.avatarUrl,
      emailVerified: true,
      status: "active",
      roles: ["user"],
    });
    await LinkedAccount.create({ userId: user._id, provider, providerAccountId: profile.sub, email: profile.email });
    await recordEvent({ action: "account.registered", subjectId: user._id, clientId: meta.mobileMfa?.clientId, request: meta, data: { method: provider } });
  }

  if (isBlockedUser(user)) {
    throw new AppError("Unable to sign in", 401, "invalid_credentials");
  }

  // The account's own address counts as proved only when the provider proved that same address.
  if (profile.emailVerified && profile.email === user.email) {
    user.emailVerified = true;
    if (user.status === "pending_verification") user.status = "active";
  }
  if (!user.emailVerified || user.status !== "active") {
    throw new AppError("Confirm your email address before signing in.", 403, "email_not_verified");
  }
  if (!user.avatarUrl && profile.avatarUrl) {
    user.avatarUrl = profile.avatarUrl;
  }
  // A risky sign-in asks for a second step even when it's optional (lib/security/risk.ts).
  await requireSecondFactor(user._id.toString(), meta.mobileMfa, provider, await assessSignInRisk(user._id, meta));

  user.lastLoginAt = new Date();
  await user.save();

  const { token } = await createSession({ userId: user._id, ipAddress: meta.ipAddress, userAgent: meta.userAgent, place: meta.place, deviceId: meta.deviceId, methods: [provider] });
  await recordEvent({ action: "auth.signed_in", subjectId: user._id, clientId: meta.mobileMfa?.clientId, request: meta, data: { methods: [provider] } });

  return { user: toPublicUser(user), sessionToken: token };
}
