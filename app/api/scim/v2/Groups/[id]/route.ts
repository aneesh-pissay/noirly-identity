import { readScimBody, scimJson, scimRoute } from "@/lib/scim/http";
import { deleteScimGroup, getScimGroup, patchScimGroup, replaceScimGroup } from "@/lib/scim/groups";

type P = { id: string };

export const GET = scimRoute<P>(async ({ organizationId, params }) => scimJson(await getScimGroup(organizationId, params.id)));
export const PUT = scimRoute<P>(async ({ request, organizationId, params }) => scimJson(await replaceScimGroup(organizationId, params.id, await readScimBody(request))));
export const PATCH = scimRoute<P>(async ({ request, organizationId, params }) => scimJson(await patchScimGroup(organizationId, params.id, await readScimBody(request))));
export const DELETE = scimRoute<P>(async ({ organizationId, params }) => {
  await deleteScimGroup(organizationId, params.id);
  return scimJson(null, 204);
});
