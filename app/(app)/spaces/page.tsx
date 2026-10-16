import { redirect } from "next/navigation";
import { SpacesManager } from "@/components/SpacesManager";
import { withDb } from "@/lib/api/with-db";
import { getRequestUser } from "@/lib/auth/request-user";
import { listSpacesForUser } from "@/lib/spaces/space-service";

export default async function SpacesPage() {
  const user = await getRequestUser();
  if (!user) {
    redirect("/login?return_to=/spaces");
  }
  const spaces = await withDb(() => listSpacesForUser(user.id));
  return <SpacesManager userId={user.id} initialSpaces={spaces} />;
}
