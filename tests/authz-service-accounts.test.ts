import { describe, expect, it } from "vitest";
import { NextRequest } from "next/server";
import { decodeJwt } from "jose";
import { POST as tokenRoute } from "@/app/api/oauth/token/route";
import { POST as checkRoute } from "@/app/api/authz/check/route";
import { assignRole, saveRole } from "@/lib/authz/admin";
import { createServiceAccount, disableServiceAccount, listServiceAccounts, rotateServiceAccountSecret } from "@/lib/authz/service-accounts";
import { validateAuthorizeRequest } from "@/lib/oauth/authorize";
import { createSpace } from "@/lib/spaces/space-service";
import { createTestUser } from "./helpers";

const basic = (id: string, secret: string) => `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`;
const tokenFor = async (clientId: string, secret: string) =>
  tokenRoute(new NextRequest("http://localhost:3000/api/oauth/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", authorization: basic(clientId, secret) }, body: "grant_type=client_credentials" }));
const check = (token: string, permission: string) =>
  checkRoute(new NextRequest("http://localhost:3000/api/authz/check", { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify({ permission }) }));

async function setup() {
  const { user: owner } = await createTestUser({ email: "owner@example.com" });
  const ownerId = String(owner._id);
  const space = await createSpace({ ownerId, name: "Data Co" });
  const role = await saveRole(ownerId, space.id, { name: "Exporter", permissions: ["export:run", "report:read"] });
  const created = await createServiceAccount(ownerId, space.id, "Nightly export");
  return { ownerId, space, role, ...created };
}

describe("service accounts", () => {
  it("have their own credentials and only the privileges their organization delegates", async () => {
    const { ownerId, space, role, serviceAccount, clientSecret } = await setup();
    let token = (await (await tokenFor(serviceAccount.clientId, clientSecret)).json()).access_token as string;
    expect(decodeJwt(token)).toMatchObject({ sub: serviceAccount.clientId, org_id: space.id, permissions: [] });
    expect(await (await check(token, "export:run")).json()).toEqual({ allowed: false });

    await assignRole(ownerId, space.id, { roleId: role.id, subjectType: "service", subjectId: serviceAccount.id });
    token = (await (await tokenFor(serviceAccount.clientId, clientSecret)).json()).access_token;
    expect(decodeJwt(token).permissions).toEqual(["export:run", "report:read"]);
    expect(await (await check(token, "export:run")).json()).toEqual({ allowed: true });
    expect(await (await check(token, "user:delete")).json()).toEqual({ allowed: false });
  });

  it("never sign people in", async () => {
    const { serviceAccount } = await setup();
    await expect(validateAuthorizeRequest({ client_id: serviceAccount.clientId, redirect_uri: "urn:noirly:service-account", response_type: "code", scope: "openid", state: "s" })).rejects.toMatchObject({ error: "unauthorized_client" });
  });

  it("can have their secret replaced, and be disabled, which stops their tokens at once", async () => {
    const { ownerId, space, serviceAccount, clientSecret } = await setup();
    const token = (await (await tokenFor(serviceAccount.clientId, clientSecret)).json()).access_token as string;
    const rotated = await rotateServiceAccountSecret(ownerId, space.id, serviceAccount.id);
    expect((await tokenFor(serviceAccount.clientId, clientSecret)).status).toBe(401);
    // The old secret's tokens went with it.
    expect((await check(token, "export:run")).status).toBe(401);
    const fresh = (await (await tokenFor(serviceAccount.clientId, rotated.clientSecret)).json()).access_token as string;

    await disableServiceAccount(ownerId, space.id, serviceAccount.id);
    expect((await check(fresh, "export:run")).status).toBe(401);
    expect((await tokenFor(serviceAccount.clientId, rotated.clientSecret)).status).toBe(401);
    expect((await listServiceAccounts(ownerId, space.id))[0]).toMatchObject({ name: "Nightly export", disabled: true });
  });

  it("are created by admins with the access area only", async () => {
    const { space } = await setup();
    const { user: member } = await createTestUser({ email: "member@example.com" });
    const { OrganizationMembership } = await import("@/models/OrganizationMembership");
    await OrganizationMembership.create({ organizationId: space.id, userId: member._id, role: "member" });
    await expect(createServiceAccount(String(member._id), space.id, "Mine")).rejects.toMatchObject({ status: 403 });
  });
});
