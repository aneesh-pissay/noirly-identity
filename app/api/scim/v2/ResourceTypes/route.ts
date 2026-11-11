import { listResponse, SCHEMA, scimJson, scimRoute } from "@/lib/scim/http";

export const GET = scimRoute(async () =>
  scimJson(
    listResponse(
      [
        { schemas: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], id: "User", name: "User", endpoint: "/Users", schema: SCHEMA.user },
        { schemas: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], id: "Group", name: "Group", endpoint: "/Groups", schema: SCHEMA.group },
      ],
      2,
      1,
    ),
  ),
);
