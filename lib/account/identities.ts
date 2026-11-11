import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { recordEvent, type RequestMeta } from "@/lib/audit/event-log";
import { isGoogleOAuthConfigured } from "@/lib/auth/google";
import { isAppleConfigured } from "@/lib/auth/apple";
import { isProviderConfigured } from "@/lib/auth/oauth-providers";
import type { ProviderProfile } from "@/lib/auth/provider-login";
import { LinkedAccount } from "@/models/LinkedAccount";
import { Passkey } from "@/models/SecurityCredential";
import { User } from "@/models/User";
import { hashPassword } from "@/lib/security/password";
import { revokeAllUserSessions } from "@/lib/sessions/session-service";
import { assertNotBreached } from "@/lib/security/breached-passwords";
import { methodCount, PROVIDER_LABEL, PROVIDERS, type MethodCounts, type Provider, type SignInMethods } from "@/lib/account/sign-in-methods";

/**
 * The ways an account signs in: a password, passkeys (each a whole sign-in
 * on its own), and linked providers (Google, Apple, Microsoft, GitHub). One can be added or
 * removed from settings, but never the last: an account always keeps a way
 * in besides an emailed reset.
 */

type Counts = MethodCounts;

function oid(id: string) {
  if (!Types.ObjectId.isValid(id)) throw new AppError("Invalid account", 400, "invalid_request");
  return new Types.ObjectId(id);
}

async function countsFor(userId: Types.ObjectId): Promise<Counts> {
  const [user, passkeys, providers] = await Promise.all([
    User.findById(userId).select("+passwordHash").lean(),
    // Only keys that sign in by themselves: a second-step-only key is no way in alone.
    Passkey.countDocuments({ userId, standalone: { $ne: false } }),
    LinkedAccount.countDocuments({ userId }),
  ]);
  if (!user) throw new AppError("Authentication required", 401, "unauthorized");
  return { password: Boolean(user.passwordHash), passkeys, providers };
}

/** Refuses a removal that would leave no way to sign in. */
export async function assertKeepsAWayIn(userId: string, removing: Partial<Counts>) {
  const counts = await countsFor(oid(userId));
  const after = {
    password: counts.password && !removing.password,
    passkeys: counts.passkeys - (removing.passkeys ?? 0),
    providers: counts.providers - (removing.providers ?? 0),
  };
  if (methodCount(after) < 1) {
    throw new AppError("This is your only way to sign in. Add a password, a passkey or another account first.", 409, "last_sign_in_method");
  }
}

/** Whether this provider is set up here, so it can be signed in with and linked. */
export function providerAvailable(provider: Provider): boolean {
  if (provider === "google") return isGoogleOAuthConfigured();
  if (provider === "apple") return isAppleConfigured();
  return isProviderConfigured(provider);
}

export async function listSignInMethods(userId: string): Promise<SignInMethods> {
  const id = oid(userId);
  const counts = await countsFor(id);
  const links = await LinkedAccount.find({ userId: id }).lean();
  return {
    password: counts.password,
    passkeys: counts.passkeys,
    providers: PROVIDERS.map((provider) => {
      const link = links.find((l) => l.provider === provider);
      return {
        provider,
        available: providerAvailable(provider),
        linked: link ? { email: link.email ?? null, linkedAt: link.createdAt.toISOString() } : null,
      };
    }),
  };
}

/**
 * Links the provider account that just proved itself to this Identity
 * account, from settings. One account per provider, and a provider account
 * already linked elsewhere stays there.
 */
export async function linkProvider(provider: Provider, userId: string, profile: ProviderProfile, meta: RequestMeta = {}) {
  const id = oid(userId);
  const label = PROVIDER_LABEL[provider];
  const existing = await LinkedAccount.findOne({ provider, providerAccountId: profile.sub }).lean();
  if (existing) {
    if (existing.userId.equals(id)) return;
    throw new AppError(`That ${label} account is already linked to another Noirly account.`, 409, "linked_elsewhere");
  }
  if (await LinkedAccount.exists({ userId: id, provider })) {
    throw new AppError(`Another ${label} account is already linked. Unlink it first.`, 409, "already_linked");
  }
  await LinkedAccount.create({ userId: id, provider, providerAccountId: profile.sub, email: profile.email });
  await recordEvent({ action: "account.identity_linked", subjectId: id, request: meta, data: { provider, email: profile.email, fromSettings: true } });
}

export function linkGoogle(userId: string, profile: ProviderProfile, meta: RequestMeta = {}) {
  return linkProvider("google", userId, profile, meta);
}

export async function unlinkProvider(userId: string, provider: Provider, meta: RequestMeta = {}) {
  const id = oid(userId);
  const link = await LinkedAccount.findOne({ userId: id, provider }).lean();
  if (!link) throw new AppError("That account isn't linked", 404, "not_found");
  await assertKeepsAWayIn(userId, { providers: 1 });
  await LinkedAccount.deleteOne({ _id: link._id });
  await recordEvent({ action: "account.identity_unlinked", subjectId: id, request: meta, data: { provider, email: link.email ?? null } });
  return listSignInMethods(userId);
}

/** Adds a password to an account that has none (one with a password changes it the usual way, with the current one). */
export async function setPassword(userId: string, password: string, meta: RequestMeta = {}) {
  const user = await User.findById(oid(userId)).select("+passwordHash");
  if (!user) throw new AppError("Authentication required", 401, "unauthorized");
  if (user.passwordHash) throw new AppError("You already have a password. Change it with your current one.", 409, "password_exists");
  await assertNotBreached(password);
  user.passwordHash = await hashPassword(password);
  await user.save();
  await recordEvent({ action: "password.set", subjectId: user._id, request: meta });
  return listSignInMethods(userId);
}

/**
 * Removes the password, for accounts that sign in other ways (a passkey, a
 * linked provider). Never the last way in; signs out everywhere else, since
 * a session someone started with that password shouldn't outlive it.
 */
export async function removePassword(userId: string, keepSessionId: string, meta: RequestMeta = {}) {
  const user = await User.findById(oid(userId)).select("+passwordHash");
  if (!user) throw new AppError("Authentication required", 401, "unauthorized");
  if (!user.passwordHash) throw new AppError("You don't have a password", 404, "not_found");
  await assertKeepsAWayIn(userId, { password: true });
  user.passwordHash = null;
  await user.save();
  await revokeAllUserSessions(user._id, keepSessionId);
  await recordEvent({ action: "password.removed", subjectId: user._id, request: meta, data: { otherSessionsSignedOut: true } });
  return listSignInMethods(userId);
}
