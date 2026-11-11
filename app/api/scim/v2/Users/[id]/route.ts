import { readScimBody, scimJson, scimRoute } from "@/lib/scim/http";
import { deleteScimUser, getScimUser, patchScimUser, replaceScimUser } from "@/lib/scim/users";

type P = { id: string };

export const GET = scimRoute<P>(async ({ organizationId, params }) => scimJson(await getScimUser(organizationId, params.id)));
export const PUT = scimRoute<P>(async ({ request, organizationId, params }) => scimJson(await replaceScimUser(organizationId, params.id, await readScimBody(request))));
export const PATCH = scimRoute<P>(async ({ request, organizationId, params }) => scimJson(await patchScimUser(organizationId, params.id, await readScimBody(request))));
export const DELETE = scimRoute<P>(async ({ organizationId, params }) => {
  await deleteScimUser(organizationId, params.id);
  return scimJson(null, 204);
});
