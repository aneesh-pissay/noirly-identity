import { normalizeEmail } from "@/lib/auth/user-mapper";
import { isBlockedUser } from "@/lib/auth/user-policy";
import { providerAvailable } from "@/lib/account/identities";
import { PROVIDERS, type Provider } from "@/lib/account/sign-in-methods";
import { consumeRateLimit } from "@/lib/security/shared-rate-limit";
import { LinkedAccount } from "@/models/LinkedAccount";
import { Passkey } from "@/models/SecurityCredential";
import { User } from "@/models/User";
import { PROVIDER_SIGN_IN_ENABLED } from "@/lib/auth/provider-login";

/**
 * Email-first sign-in: after someone types their address, which ways to
 * offer them. An address with no account gets exactly what an ordinary
 * password account gets (password and an emailed link), so the answer can't
 * tell the two apart. Accounts that can't use a password are steered to what
 * they can use, which does show such an account exists: the price of not
 * offering a password that would never work. Answers are rate-limited per
 * address, and past the limit everyone gets the ordinary answer.
 *
 * An organisation's verified domain with an identity provider routes its
 * people to the organisation's own sign-in here, before anything else.
 */

export type SignInOptions = {
  email: string;
  password: boolean;
  passkey: boolean;
  providers: Provider[];
  emailLink: boolean;
  /** The address's domain signs in through its organization's IdP: where to start, and whether it's the only way. */
  sso?: { startUrl: string; name: string; required: boolean };
};

/** Lookups one address answers in an hour, before it gets the ordinary answer. */
const LOOKUPS_PER_HOUR = 10;

function ordinary(email: string): SignInOptions {
  return { email, password: true, passkey: false, providers: [], emailLink: true };
}

export async function discoverSignIn(rawEmail: string): Promise<SignInOptions> {
  const email = normalizeEmail(rawEmail);
  // An organization's verified domain goes to its own sign-in first. This depends only on the
  // domain (public in DNS anyway), never on whether the address has an account.
  const { findProvider } = await import("@/lib/federation/sso");
  const idp = await findProvider({ email });
  if (idp) {
    const { enforcedProviderFor } = await import("@/lib/federation/enforcement");
    const required = Boolean(await enforcedProviderFor(email));
    const sso = { startUrl: `/api/sso/start?email=${encodeURIComponent(email)}`, name: idp.name, required };
    // Required: only the organization's sign-in is offered (break-glass accounts use the password page directly).
    if (required) return { email, password: false, passkey: false, providers: [], emailLink: false, sso };
    return { ...(await discoverAccount(email)), sso };
  }
  return discoverAccount(email);
}

async function discoverAccount(email: string): Promise<SignInOptions> {
  const limited = await consumeRateLimit(`discover:${email}`, LOOKUPS_PER_HOUR, 3600);
  if (!limited.allowed) return ordinary(email);
  const user = await User.findOne({ email }).select("+passwordHash").lean();
  if (!user || isBlockedUser(user)) return ordinary(email);

  const [links, passkeys] = await Promise.all([
    LinkedAccount.find({ userId: user._id }).select("provider").lean(),
    Passkey.exists({ userId: user._id, standalone: { $ne: false } }),
  ]);
  // Linked providers never sign in, so they're never offered (the field stays for older clients).
  const providers = PROVIDER_SIGN_IN_ENABLED ? PROVIDERS.filter((p) => providerAvailable(p) && links.some((l) => l.provider === p)) : [];
  const password = Boolean(user.passwordHash);
  // A password account looks like any other: its providers and passkeys aren't shown.
  if (password) return ordinary(email);
  return {
    email,
    // Nothing else works for it: offer the password box anyway, with the reset link beside it.
    password: providers.length === 0 && !passkeys,
    passkey: Boolean(passkeys),
    providers,
    // Offered to every account alike; one that can't use it (unconfirmed) simply gets no email.
    emailLink: true,
  };
}
