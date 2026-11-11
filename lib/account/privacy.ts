import { Types } from "mongoose";
import { getRetention } from "@/lib/audit/retention";
import { userStream } from "@/lib/audit/chain";
import { AppAccess } from "@/models/AppAccess";
import { Avatar } from "@/models/Avatar";
import { IdentityEvent } from "@/models/IdentityEvent";
import { LinkedAccount } from "@/models/LinkedAccount";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { Mfa, Passkey } from "@/models/SecurityCredential";
import { Session } from "@/models/Session";
import { SignInRecord } from "@/models/SignInRecord";
import { User } from "@/models/User";
import { UserEmail } from "@/models/UserEmail";

/**
 * The privacy dashboard's summary: what Identity holds about an account, by
 * kind, how much, why, and for how long. The full data itself is the export
 * (lib/account/closure.ts, `exportIdentityData`).
 */

export type PrivacyCategory = { id: string; label: string; count: number; why: string; kept: string };

export async function privacySummary(userIdInput: string): Promise<PrivacyCategory[]> {
  const userId = new Types.ObjectId(userIdInput);
  const now = new Date();
  const [user, emails, providers, passkeys, authenticator, sessions, history, apps, spaces, events, avatar, retention] = await Promise.all([
    User.findById(userId).select("phoneNumber phoneVerifiedAt recoveryEmail recoveryEmailVerifiedAt locale zoneinfo accessibility").lean(),
    UserEmail.countDocuments({ userId }),
    LinkedAccount.countDocuments({ userId }),
    Passkey.countDocuments({ userId }),
    Mfa.countDocuments({ userId, enabled: true }),
    Session.countDocuments({ userId, revokedAt: null, expiresAt: { $gt: now } }),
    SignInRecord.countDocuments({ userId }),
    AppAccess.countDocuments({ userId, removedAt: null }),
    OrganizationMembership.countDocuments({ userId }),
    IdentityEvent.countDocuments({ stream: userStream(userIdInput) }),
    Avatar.countDocuments({ userId }),
    getRetention(),
  ]);
  const kept = (days: number | null) => (days === null ? "Until you delete your account" : `${days} days, then removed`);
  return [
    { id: "profile", label: "Your profile", count: 1, why: "Your name, and your language, time zone and accessibility choices, which apps use to show things your way.", kept: "Until you change it or delete your account" },
    { id: "emails", label: "Email addresses", count: 1 + emails, why: "To sign you in, and to reach you about your account.", kept: "Until you remove them" },
    { id: "phone", label: "Phone number", count: user?.phoneNumber && user.phoneVerifiedAt ? 1 : 0, why: "Only to reach you about your account's security; never a way to sign in.", kept: "Until you remove it" },
    { id: "recovery", label: "Recovery address", count: user?.recoveryEmail && user.recoveryEmailVerifiedAt ? 1 : 0, why: "Only to prove it's you if you lose a second step.", kept: "Until you remove it" },
    { id: "sign-in", label: "Ways to sign in", count: providers + passkeys + authenticator, why: "Linked providers, passkeys and authenticator apps, so you can sign in. Secrets are never stored in readable form.", kept: "Until you remove them" },
    { id: "photo", label: "Profile photo", count: avatar, why: "Shown to you and the apps you allow.", kept: "Until you remove it" },
    { id: "sessions", label: "Signed-in devices", count: sessions, why: "To keep you signed in, and so you can see and sign out each one.", kept: "Until each signs out or expires" },
    { id: "history", label: "Sign-in history", count: history, why: "When, roughly where (country), and on which device you signed in, to spot sign-ins that aren't you.", kept: "One year" },
    { id: "apps", label: "Apps you've let in", count: apps, why: "Which apps signed you in and what each may see, so you can review and remove them.", kept: "Until you remove an app's access" },
    { id: "spaces", label: "Spaces", count: spaces, why: "The teams you belong to and your role in each, which apps use for sharing.", kept: "Until you leave" },
    { id: "activity", label: "Security activity", count: events, why: "A tamper-evident record of sign-ins and changes to your account, for you and for investigating misuse.", kept: kept(retention.accountDays) },
  ];
}
