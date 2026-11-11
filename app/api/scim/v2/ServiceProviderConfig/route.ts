import { scimJson, scimRoute } from "@/lib/scim/http";

/** What this SCIM service supports (RFC 7643 §5). */
export const GET = scimRoute(async () =>
  scimJson({
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
    patch: { supported: true },
    bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults: 200 },
    changePassword: { supported: false },
    sort: { supported: false },
    etag: { supported: false },
    authenticationSchemes: [{ type: "oauthbearertoken", name: "Bearer token", description: "A provisioning token from the space's settings", primary: true }],
    meta: { resourceType: "ServiceProviderConfig" },
  }),
);
