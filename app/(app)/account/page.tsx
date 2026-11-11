import { redirect } from "next/navigation";
import { SecuritySettings } from "@/components/security/SecuritySettings";
import { SecurityActivity } from "@/components/security/SecurityActivity";
import { EmailAddresses } from "@/components/security/EmailAddresses";
import { PhoneNumber } from "@/components/security/PhoneNumber";
import { RecoveryMethods } from "@/components/security/RecoveryMethods";
import { FreezeAccount } from "@/components/security/FreezeAccount";
import { Preferences } from "@/components/security/Preferences";
import { SignInMethods } from "@/components/security/SignInMethods";
import { ConnectedApps } from "@/components/security/ConnectedApps";
import { DeviceSessions } from "@/components/security/DeviceSessions";
import { SessionLifetime } from "@/components/security/SessionLifetime";
import { MergeAccounts } from "@/components/security/MergeAccounts";
import { AccountSettings } from "@/components/AccountSettings";
import { getRequestUser } from "@/lib/auth/request-user";
import { sanitizeReturnTo } from "@/lib/auth/return-to";
import { getEnv } from "@/lib/config/env";
import { withDb } from "@/lib/api/with-db";
import { OAuthClient } from "@/models/OAuthClient";
import { ownsAnyApp } from "@/lib/oauth/app-owners";

export default async function AccountPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const user = await getRequestUser();

  if (!user) {
    redirect("/login?return_to=/account");
  }

  // Back from linking a provider: how it went.
  const params = await searchParams;
  const one = (value: string | string[] | undefined) => (typeof value === "string" ? value.slice(0, 200) : null);
  // Sent here by an app that requires a second step: its registered name, never text from the address.
  const mfaForId = one(params.mfa_for);
  const mfaFor = mfaForId ? ((await withDb(() => OAuthClient.findOne({ clientId: mfaForId }).select("name").lean()))?.name ?? null) : null;

  return <>
    <AccountSettings initialUser={user} ownsApps={user.roles.includes("admin") || (await withDb(() => ownsAnyApp(user.id)))} />
    <EmailAddresses />
    <PhoneNumber />
    <RecoveryMethods />
    <Preferences initial={{ locale: user.locale, zoneinfo: user.zoneinfo, accessibility: user.accessibility }} />
    <SignInMethods linked={one(params.linked)} linkError={one(params.link_error)} provider={one(params.provider)} />
    <SecuritySettings mfaFor={mfaFor} returnTo={sanitizeReturnTo(one(params.return_to), getEnv().APP_URL)} />
    <DeviceSessions />
    <SessionLifetime />
    <ConnectedApps />
    <MergeAccounts />
    <FreezeAccount />
    <SecurityActivity />
  </>;
}
