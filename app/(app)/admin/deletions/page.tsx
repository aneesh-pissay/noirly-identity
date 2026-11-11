import { redirect } from "next/navigation";
import { AdminDeletions } from "@/components/AdminDeletions";
import { getRequestUser } from "@/lib/auth/request-user";

/** Admin: which apps confirmed each account deletion. */
export default async function AdminDeletionsPage() {
  const user = await getRequestUser();
  if (!user) redirect("/login?return_to=/admin/deletions");
  if (!user.roles.includes("admin")) redirect("/account");
  return <AdminDeletions />;
}
