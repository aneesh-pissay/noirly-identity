import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { GET as authorize } from "@/app/api/oauth/authorize/route";
import { getEnv } from "@/lib/config/env";
import { exchangeAuthorizationCode, exchangeRefreshToken } from "@/lib/oauth/token";
import { generateSecureToken } from "@/lib/security/crypto";
import { createSession } from "@/lib/sessions/session-service";
import { getOrgApps, orgAllowsApp, removeOrgApp, setOrgApp, setOrgAppsMode } from "@/lib/spaces/org-apps";
import { createSpace, setAdminAreas } from "@/lib/spaces/space-service";
import { createTeam, setTeamMember } from "@/lib/spaces/teams";
import { createTestClient, createTestUser, pkceChallenge } from "./helpers";

const jar = vi.hoisted(() => new Map<string, string>());
vi.mock("next/headers", () => ({ cookies: async () => ({ get: (key: string) => (jar.has(key) ? { value: jar.get(key) } : undefined) }) }));
beforeEach(() => jar.clear());

async function setup() {
  const { user: owner } = await createTestUser({ email: "owner@example.com" });
  const { user: admin } = await createTestUser({ email: "admin@example.com" });
  const { user: alice } = await createTestUser({ email: "alice@example.com" });
  const space = await createSpace({ ownerId: String(owner._id), name: "Studio", members: [{ userId: String(admin._id), role: "admin" }, { userId: String(alice._id), role: "member" }] });
  const { client, clientSecret } = await createTestClient();
  return { ownerId: String(owner._id), adminId: String(admin._id), aliceId: String(alice._id), space, client, clientSecret };
}

async function openInOrg(userId: string, client: { clientId: string; redirectUris: string[] }, organization: string, extra: Record<string, string> = {}) {
  const { token } = await createSession({ userId, methods: ["password"] });
  jar.clear();
  jar.set(getEnv().SESSION_COOKIE_NAME, token);
  const verifier = generateSecureToken(32);
  const url = new URL("http://localhost:3000/api/oauth/authorize");
  for (const [k, v] of Object.entries({ client_id: client.clientId, redirect_uri: client.redirectUris[0]!, response_type: "code", scope: "openid offline_access", state: "st", code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", organization, ...extra })) url.searchParams.set(k, v);
  return { location: new URL((await authorize(new NextRequest(url))).headers.get("location")!), verifier };
}

describe("apps per organization", () => {
  it("are open by default, and once listed only the listed apps open, for the people each allows", async () => {
    const { ownerId, aliceId, space, client } = await setup();
    expect(await orgAllowsApp(space.id, aliceId, client)).toBe(true);

    await setOrgAppsMode(ownerId, space.id, "listed");
    expect(await orgAllowsApp(space.id, aliceId, client)).toBe(false);
    expect((await openInOrg(aliceId, client, space.id)).location.pathname).toBe("/no-access");
    expect((await openInOrg(aliceId, client, space.id, { prompt: "none" })).location.searchParams.get("error")).toBe("access_denied");

    await setOrgApp(ownerId, space.id, { appKey: client.clientId, access: "everyone" });
    expect((await openInOrg(aliceId, client, space.id)).location.searchParams.get("code")).toBeTruthy();

    await setOrgApp(ownerId, space.id, { appKey: client.clientId, access: "admins" });
    expect(await orgAllowsApp(space.id, aliceId, client)).toBe(false);
    expect(await orgAllowsApp(space.id, ownerId, client)).toBe(true);
  });

  it("can be limited to teams, counting sub-team members", async () => {
    const { ownerId, aliceId, space, client } = await setup();
    const design = await createTeam(ownerId, space.id, { name: "Design" });
    const brand = await createTeam(ownerId, space.id, { name: "Brand", parentId: design.id });
    await setOrgAppsMode(ownerId, space.id, "listed");
    await setOrgApp(ownerId, space.id, { appKey: client.clientId, access: "teams", teamIds: [design.id] });
    expect(await orgAllowsApp(space.id, aliceId, client)).toBe(false);
    await setTeamMember(ownerId, space.id, brand.id, aliceId, true);
    expect(await orgAllowsApp(space.id, aliceId, client)).toBe(true);
    await expect(setOrgApp(ownerId, space.id, { appKey: client.clientId, access: "teams", teamIds: [] })).rejects.toMatchObject({ status: 400 });
  });

  it("end a grant at the next refresh once the organization stops allowing the app", async () => {
    const { ownerId, aliceId, space, client, clientSecret } = await setup();
    const { location, verifier } = await openInOrg(aliceId, client, space.id);
    const tokens = await exchangeAuthorizationCode({ code: location.searchParams.get("code")!, redirectUri: client.redirectUris[0]!, codeVerifier: verifier, clientId: client.clientId, clientSecret, authorizationHeader: null });
    await setOrgAppsMode(ownerId, space.id, "listed");
    await expect(exchangeRefreshToken({ refreshToken: tokens.refresh_token!, clientId: client.clientId, clientSecret, authorizationHeader: null })).rejects.toMatchObject({ error: "invalid_grant" });
  });

  it("are managed by admins with the apps area, and listed for members to see", async () => {
    const { ownerId, adminId, aliceId, space, client } = await setup();
    await setOrgApp(adminId, space.id, { appKey: client.clientId, access: "everyone" });
    await setAdminAreas(ownerId, space.id, adminId, ["members"]);
    await expect(setOrgAppsMode(adminId, space.id, "listed")).rejects.toMatchObject({ status: 403 });
    await expect(setOrgApp(aliceId, space.id, { appKey: client.clientId, access: "admins" })).rejects.toMatchObject({ status: 403 });
    const seen = await getOrgApps(aliceId, space.id);
    expect(seen.apps).toEqual([{ appKey: client.clientId, name: "Test App", access: "everyone", teamIds: [] }]);
    expect(seen.available.map((a) => a.appKey)).toContain(client.clientId);
    await removeOrgApp(ownerId, space.id, client.clientId);
    expect((await getOrgApps(ownerId, space.id)).apps).toEqual([]);
  });
});
