import { redirect } from "next/navigation";
import { AccountPageHeader, AccountSections } from "@/components/account/AccountPageHeader";
import { DeviceSessions } from "@/components/security/DeviceSessions";
import { SecurityActivity } from "@/components/security/SecurityActivity";
import { SessionLifetime } from "@/components/security/SessionLifetime";
import { getRequestUser } from "@/lib/auth/request-user";

export const metadata = { title: "Devices · Noirly Identity" };

/** Where you're signed in, for how long, and what's happened on the account. */
export default async function DevicesPage() {
  const user = await getRequestUser();
  if (!user) redirect("/login?return_to=/account/devices");
  return (
    <>
      <AccountPageHeader title="Devices" lead="Everywhere you're signed in, how long you stay signed in, and recent sign-ins and changes." />
      <AccountSections>
        <DeviceSessions />
        <SessionLifetime />
        <SecurityActivity />
      </AccountSections>
    </>
  );
}
