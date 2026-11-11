import { redirect } from "next/navigation";
import { ClientGenerator } from "@/components/ClientGenerator";
import { withDb } from "@/lib/api/with-db";
import { getRequestUser } from "@/lib/auth/request-user";
import { getEnv } from "@/lib/config/env";
import { clientsVisibleTo, ownerEmails, ownsAnyApp } from "@/lib/oauth/app-owners";
import { listOAuthClients } from "@/lib/oauth/client-admin";

/** Admins manage every app here; app owners manage theirs. */
export default async function ClientsPage() {
  const user = await getRequestUser();

  if (!user) {
    redirect("/login?return_to=/clients");
  }
  const isAdmin = user.roles.includes("admin");
  if (!isAdmin && !(await withDb(() => ownsAnyApp(user.id)))) {
    redirect("/account");
  }

  const { clients, owners } = await withDb(async () => {
    const clients = await listOAuthClients(clientsVisibleTo({ user, isAdmin }));
    return { clients, owners: await ownerEmails(clients.flatMap((c) => c.ownerIds)) };
  });

  return <ClientGenerator issuer={getEnv().OIDC_ISSUER} initialClients={clients} isAdmin={isAdmin} initialOwners={owners} />;
}
