import { redirect } from "next/navigation";
import { AccountPageHeader, AccountSections } from "@/components/account/AccountPageHeader";
import { ProfileForm } from "@/components/account/ProfileForm";
import { EmailAddresses } from "@/components/security/EmailAddresses";
import { PhoneNumber } from "@/components/security/PhoneNumber";
import { Preferences } from "@/components/security/Preferences";
import { getRequestUser } from "@/lib/auth/request-user";

export const metadata = { title: "Personal info · Noirly Identity" };

/** Who you are to Noirly apps: name and photo, addresses, phone, language and accessibility. */
export default async function PersonalInfoPage() {
  const user = await getRequestUser();
  if (!user) redirect("/login?return_to=/account/profile");
  return (
    <>
      <AccountPageHeader title="Personal info" lead="What Noirly apps know about you, and how they show it." />
      <AccountSections>
        <ProfileForm initialUser={user} />
        <EmailAddresses />
        <PhoneNumber />
        <Preferences initial={{ locale: user.locale, zoneinfo: user.zoneinfo, accessibility: user.accessibility }} />
      </AccountSections>
    </>
  );
}
