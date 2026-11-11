import { redirect } from "next/navigation";
import { AdminSecurity } from "@/components/AdminSecurity";
import { getRequestUser } from "@/lib/auth/request-user";

/** Admin: account takeover containment. */
export default async function AdminSecurityPage() {
  const user = await getRequestUser();
  if (!user) redirect("/login?return_to=/admin/security");
  if (!user.roles.includes("admin")) redirect("/account");
  return <AdminSecurity />;
}
