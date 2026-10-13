import { redirect } from "next/navigation";
import { SecuritySettings } from "@/components/security/SecuritySettings";
import { AccountSettings } from "@/components/AccountSettings";
import { getRequestUser } from "@/lib/auth/request-user";

export default async function AccountPage() {
  const user = await getRequestUser();

  if (!user) {
    redirect("/login?return_to=/account");
  }

  return <><AccountSettings initialUser={user} /><SecuritySettings /></>;
}
