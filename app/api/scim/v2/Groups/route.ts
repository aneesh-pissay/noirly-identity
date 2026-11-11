import { paging, readScimBody, scimJson, scimRoute } from "@/lib/scim/http";
import { createScimGroup, listScimGroups } from "@/lib/scim/groups";

export const GET = scimRoute(async ({ request, organizationId }) => {
  const { startIndex, count } = paging(request);
  const excluded = request.nextUrl.searchParams.get("excludedAttributes")?.toLowerCase().split(",").includes("members") ?? false;
  return scimJson(await listScimGroups(organizationId, request.nextUrl.searchParams.get("filter"), startIndex, count, excluded));
});

export const POST = scimRoute(async ({ request, organizationId }) => {
  const group = await createScimGroup(organizationId, await readScimBody(request));
  return scimJson(group, 201, { location: group.meta.location });
});
