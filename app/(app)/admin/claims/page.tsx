import { redirect } from "next/navigation";
import { AdminClaims } from "@/components/AdminClaims";
import { getRequestUser } from "@/lib/auth/request-user";

/** Admin: claim minimization review. */
export default async function AdminClaimsPage() {
  const user = await getRequestUser();
  if (!user) redirect("/login?return_to=/admin/claims");
  if (!user.roles.includes("admin")) redirect("/account");
  return <AdminClaims />;
}
