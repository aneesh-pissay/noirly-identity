import { redirect } from "next/navigation";
import { AccountPageHeader, AccountSections } from "@/components/account/AccountPageHeader";
import { PasswordForm } from "@/components/account/PasswordForm";
import { RecoveryMethods } from "@/components/security/RecoveryMethods";
import { SecuritySettings } from "@/components/security/SecuritySettings";
import { SignInMethods } from "@/components/security/SignInMethods";
import { withDb } from "@/lib/api/with-db";
import { getRequestUser } from "@/lib/auth/request-user";
import { sanitizeReturnTo } from "@/lib/auth/return-to";
import { getEnv } from "@/lib/config/env";
import { OAuthClient } from "@/models/OAuthClient";

export const metadata = { title: "Security · Noirly Identity" };

/** How you sign in, your second step, and how you'd get back in. */
export default async function SecurityPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const user = await getRequestUser();
  if (!user) redirect("/login?return_to=/account/security");
  // Back from linking a provider: how it went.
  const params = await searchParams;
  const one = (value: string | string[] | undefined) => (typeof value === "string" ? value.slice(0, 200) : null);
  // Sent here by an app that requires a second step: its registered name, never text from the address.
  const mfaForId = one(params.mfa_for);
  const mfaFor = mfaForId ? ((await withDb(() => OAuthClient.findOne({ clientId: mfaForId }).select("name").lean()))?.name ?? null) : null;
  return (
    <>
      <AccountPageHeader title="Security" lead="How you sign in, the second step that protects you if your password leaks, and how you'd get back in." />
      <AccountSections>
        <SecuritySettings mfaFor={mfaFor} returnTo={sanitizeReturnTo(one(params.return_to), getEnv().APP_URL)} />
        <SignInMethods linked={one(params.linked)} linkError={one(params.link_error)} provider={one(params.provider)} />
        <PasswordForm hasPassword={user.hasPassword} breached={Boolean(user.passwordBreached)} />
        <RecoveryMethods />
      </AccountSections>
    </>
  );
}
