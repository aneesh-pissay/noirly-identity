import { redirect } from "next/navigation";
import { ApiResourcesManager, type ApiResourceView } from "@/components/ApiResourcesManager";
import { withDb } from "@/lib/api/with-db";
import { getRequestUser } from "@/lib/auth/request-user";
import { ApiResource } from "@/models/ApiResource";
import { OAuthClient } from "@/models/OAuthClient";

/** Admin: the APIs that accept Identity access tokens. */
export default async function ApisPage() {
  const user = await getRequestUser();
  if (!user) redirect("/login?return_to=/apis");
  if (!user.roles.includes("admin")) redirect("/account");

  const { resources, clients } = await withDb(async () => {
    const [resources, clients] = await Promise.all([
      ApiResource.find({}).sort({ name: 1 }).lean(),
      OAuthClient.find({}).sort({ name: 1 }).select("clientId name").lean(),
    ]);
    return { resources, clients };
  });

  const views: ApiResourceView[] = resources.map((r) => ({
    identifier: r.identifier,
    name: r.name,
    scopes: r.scopes.map((s) => ({ name: s.name, description: s.description ?? "" })),
    accessTokenTtlSeconds: r.accessTokenTtlSeconds,
    allowedClientIds: [...r.allowedClientIds],
    machineGrants: (r.machineGrants ?? []).map((g) => ({ clientId: g.clientId, scopes: [...g.scopes] })),
    status: r.status,
  }));

  return <ApiResourcesManager initialResources={views} clients={clients.map((c) => ({ clientId: c.clientId, name: c.name }))} />;
}
