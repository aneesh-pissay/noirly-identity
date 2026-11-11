import { paging, readScimBody, scimJson, scimRoute } from "@/lib/scim/http";
import { createScimUser, listScimUsers } from "@/lib/scim/users";

export const GET = scimRoute(async ({ request, organizationId }) => {
  const { startIndex, count } = paging(request);
  return scimJson(await listScimUsers(organizationId, request.nextUrl.searchParams.get("filter"), startIndex, count));
});

export const POST = scimRoute(async ({ request, organizationId }) => {
  const user = await createScimUser(organizationId, await readScimBody(request));
  return scimJson(user, 201, { location: user.meta.location });
});
