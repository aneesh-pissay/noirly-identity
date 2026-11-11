import { listResponse, SCHEMA, scimJson, scimRoute } from "@/lib/scim/http";

const attr = (name: string, extra: Record<string, unknown> = {}) => ({ name, type: "string", multiValued: false, required: false, caseExact: false, mutability: "readWrite", returned: "default", uniqueness: "none", ...extra });

/** The attributes Identity reads and returns. */
export const GET = scimRoute(async () =>
  scimJson(
    listResponse(
      [
        {
          id: SCHEMA.user,
          name: "User",
          attributes: [
            attr("userName", { required: true, uniqueness: "server" }),
            attr("externalId"),
            { ...attr("name"), type: "complex", subAttributes: [attr("givenName"), attr("familyName"), attr("formatted", { mutability: "readOnly" })] },
            attr("displayName"),
            { ...attr("emails"), type: "complex", multiValued: true, mutability: "readOnly", subAttributes: [attr("value"), attr("type"), { ...attr("primary"), type: "boolean" }] },
            { ...attr("active"), type: "boolean" },
          ],
        },
        {
          id: SCHEMA.group,
          name: "Group",
          attributes: [attr("displayName", { required: true }), attr("externalId"), { ...attr("members"), type: "complex", multiValued: true, subAttributes: [attr("value"), attr("display", { mutability: "readOnly" })] }],
        },
      ],
      2,
      1,
    ),
  ),
);
