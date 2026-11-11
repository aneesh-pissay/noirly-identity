import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { POST as simulate } from "@/app/api/spaces/[spaceId]/access/simulate/route";
import { assignRole, saveRole } from "@/lib/authz/admin";
import { getEnv } from "@/lib/config/env";
import { createSession } from "@/lib/sessions/session-service";
import { createSpace } from "@/lib/spaces/space-service";
import { createTeam, setTeamMember } from "@/lib/spaces/teams";
import { createTestUser } from "./helpers";

const jar = vi.hoisted(() => new Map<string, string>());
vi.mock("next/headers", () => ({ cookies: async () => ({ get: (key: string) => (jar.has(key) ? { value: jar.get(key) } : undefined) }) }));
beforeEach(() => jar.clear());

async function as(userId: unknown) {
  const { token } = await createSession({ userId: String(userId) });
  jar.clear();
  jar.set(getEnv().SESSION_COOKIE_NAME, token);
  jar.set(getEnv().CSRF_COOKIE_NAME, "csrf");
}
const ask = (spaceId: string, body: unknown) =>
  simulate(new NextRequest(`http://localhost:3000/api/spaces/${spaceId}/access/simulate`, { method: "POST", headers: { "content-type": "application/json", "x-csrf-token": "csrf", origin: "http://localhost:3000" }, body: JSON.stringify(body) }), { params: Promise.resolve({ spaceId }) });

describe("policy simulation", () => {
  it("says whether someone can, through which assignment, and why the others didn't apply", async () => {
    const { user: owner } = await createTestUser({ email: "owner@example.com" });
    const { user: alice } = await createTestUser({ email: "alice@example.com" });
    const ownerId = String(owner._id);
    const aliceId = String(alice._id);
    const space = await createSpace({ ownerId, name: "Books", members: [{ userId: aliceId, role: "member" }] });
    const finance = await createTeam(ownerId, space.id, { name: "Finance" });
    await setTeamMember(ownerId, space.id, finance.id, aliceId, true);
    const approver = await saveRole(ownerId, space.id, { name: "Approver", permissions: ["invoice:approve"] });
    await assignRole(ownerId, space.id, { roleId: approver.id, subjectType: "team", subjectId: finance.id, conditions: [{ attribute: "device", op: "eq", value: "trusted" }] });
    await assignRole(ownerId, space.id, { roleId: approver.id, subjectType: "user", subjectId: aliceId, resource: "ledger/2025" });

    await as(owner._id);
    const untrusted = await (await ask(space.id, { subjectType: "user", subjectId: aliceId, permission: "invoice:approve", resource: "ledger/2026" })).json();
    expect(untrusted.allowed).toBe(false);
    expect(untrusted.notApplied.map((n: { via: string; reason: string }) => `${n.via}: ${n.reason}`).sort()).toEqual(["directly: only for ledger/2025", "team Finance: device is untrusted, needs eq trusted"]);

    // What if she signed in with a passkey?
    const trusted = await (await ask(space.id, { subjectType: "user", subjectId: aliceId, permission: "invoice:approve", resource: "ledger/2026", context: { deviceTrusted: true } })).json();
    expect(trusted).toMatchObject({ allowed: true, grantedBy: [{ role: "Approver", via: "team Finance" }] });

    const nothing = await (await ask(space.id, { subjectType: "user", subjectId: aliceId, permission: "user:delete" })).json();
    expect(nothing).toMatchObject({ allowed: false, reason: "No role grants it (denied by default)" });

    // Members can't simulate.
    await as(alice._id);
    expect((await ask(space.id, { subjectType: "user", subjectId: aliceId, permission: "invoice:approve" })).status).toBe(403);
  });
});
