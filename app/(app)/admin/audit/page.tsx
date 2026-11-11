import { redirect } from "next/navigation";
import { AdminAudit } from "@/components/AdminAudit";
import { getRequestUser } from "@/lib/auth/request-user";

/** Admin: audit search, alerts, retention and export. */
export default async function AdminAuditPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const user = await getRequestUser();
  if (!user) redirect("/login?return_to=/admin/audit");
  if (!user.roles.includes("admin")) redirect("/account");
  const params = await searchParams;
  const initial = Object.fromEntries(Object.entries(params).filter(([, v]) => typeof v === "string").map(([k, v]) => [k, (v as string).slice(0, 200)]));
  return <AdminAudit initial={initial} />;
}
