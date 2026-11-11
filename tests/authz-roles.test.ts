import { describe, expect, it } from "vitest";
import { assignRole, deleteRole, listAccess, saveRole, setMemberAttributes, unassignRole } from "@/lib/authz/admin";
import { can, effectivePermissions, explain, permissionMatches, resourceMatches } from "@/lib/authz/engine";
import { createSpace, setAdminAreas } from "@/lib/spaces/space-service";
import { createTeam, setTeamMember } from "@/lib/spaces/teams";
import { IdentityEvent } from "@/models/IdentityEvent";
import { createTestUser } from "./helpers";

async function setup() {
  const { user: owner } = await createTestUser({ email: "owner@example.com" });
  const { user: alice } = await createTestUser({ email: "alice@example.com" });
  const { user: bob } = await createTestUser({ email: "bob@example.com" });
  const ownerId = String(owner._id);
  const space = await createSpace({ ownerId, name: "Books", members: [{ userId: String(alice._id), role: "member" }, { userId: String(bob._id), role: "admin" }] });
  return { ownerId, aliceId: String(alice._id), bobId: String(bob._id), space };
}
const alice = (id: string) => ({ type: "user" as const, id });

describe("permissions and resources", () => {
  it("match exactly, by kind, or everything", () => {
    expect(permissionMatches("invoice:read", "invoice:read")).toBe(true);
    expect(permissionMatches("invoice:*", "invoice:write")).toBe(true);
    expect(permissionMatches("invoice:*", "invoices:write")).toBe(false);
    expect(permissionMatches("*", "anything:at_all")).toBe(true);
    expect(resourceMatches("*", null)).toBe(true);
    expect(resourceMatches("project/*", "project/42")).toBe(true);
    expect(resourceMatches("project/42", "project/43")).toBe(false);
    expect(resourceMatches("project/*", null)).toBe(false);
  });
});

describe("roles and assignments", () => {
  it("deny by default, and grant what a role holds, on the resources it covers", async () => {
    const { ownerId, aliceId, space } = await setup();
    expect(await explain(space.id, alice(aliceId), "invoice:read")).toMatchObject({ allowed: false, reason: "No role grants it (denied by default)" });

    const accountant = await saveRole(ownerId, space.id, { name: "Accountant", permissions: ["invoice:*", "report:read"] });
    await assignRole(ownerId, space.id, { roleId: accountant.id, subjectType: "user", subjectId: aliceId, resource: "ledger/*" });
    expect(await can(space.id, alice(aliceId), "invoice:write", "ledger/2026")).toBe(true);
    expect(await can(space.id, alice(aliceId), "invoice:write", "payroll/2026")).toBe(false);
    expect(await can(space.id, alice(aliceId), "invoice:write")).toBe(false);
    expect(await can(space.id, alice(aliceId), "user:delete", "ledger/2026")).toBe(false);
    expect(await effectivePermissions(space.id, alice(aliceId))).toEqual(["invoice:*@ledger/*", "report:read@ledger/*"]);
  });

  it("reach team members, sub-teams included, and stop at the organization's edge", async () => {
    const { ownerId, aliceId, space } = await setup();
    const finance = await createTeam(ownerId, space.id, { name: "Finance" });
    const payables = await createTeam(ownerId, space.id, { name: "Payables", parentId: finance.id });
    await setTeamMember(ownerId, space.id, payables.id, aliceId, true);
    const viewer = await saveRole(ownerId, space.id, { name: "Viewer", permissions: ["report:read"] });
    await assignRole(ownerId, space.id, { roleId: viewer.id, subjectType: "team", subjectId: finance.id });
    const decision = await explain(space.id, alice(aliceId), "report:read");
    expect(decision).toMatchObject({ allowed: true, grantedBy: [{ role: "Viewer", via: "team Finance" }] });

    // Someone outside the organization never gets anything, whatever they ask.
    const { user: stranger } = await createTestUser({ email: "x@example.com" });
    expect(await explain(space.id, alice(String(stranger._id)), "report:read")).toMatchObject({ allowed: false, reason: "Not a member of this organization" });
    await expect(assignRole(ownerId, space.id, { roleId: viewer.id, subjectType: "user", subjectId: String(stranger._id) })).rejects.toMatchObject({ code: "not_in_space" });
  });

  it("expire, and stop when unassigned or the role goes", async () => {
    const { ownerId, aliceId, space } = await setup();
    const role = await saveRole(ownerId, space.id, { name: "Temp", permissions: ["report:read"] });
    const assignment = await assignRole(ownerId, space.id, { roleId: role.id, subjectType: "user", subjectId: aliceId, expiresAt: new Date(Date.now() + 60_000).toISOString() });
    expect(await can(space.id, alice(aliceId), "report:read")).toBe(true);
    expect((await explain(space.id, alice(aliceId), "report:read", null, { now: new Date(Date.now() + 120_000) })).notApplied[0]?.reason).toMatch(/^expired/);
    await unassignRole(ownerId, space.id, assignment.id);
    expect(await can(space.id, alice(aliceId), "report:read")).toBe(false);
    await assignRole(ownerId, space.id, { roleId: role.id, subjectType: "user", subjectId: aliceId });
    await deleteRole(ownerId, space.id, role.id);
    expect((await listAccess(ownerId, space.id)).assignments).toEqual([]);
  });

  it("are managed by admins with the access area, and refuse malformed permissions", async () => {
    const { ownerId, bobId, aliceId, space } = await setup();
    await saveRole(bobId, space.id, { name: "Ok", permissions: ["a:b"] });
    await setAdminAreas(ownerId, space.id, bobId, ["members"]);
    await expect(saveRole(bobId, space.id, { name: "No", permissions: ["a:b"] })).rejects.toMatchObject({ status: 403 });
    await expect(saveRole(aliceId, space.id, { name: "No", permissions: ["a:b"] })).rejects.toMatchObject({ status: 403 });
    await expect(saveRole(ownerId, space.id, { name: "Bad", permissions: ["Invoice Read"] })).rejects.toMatchObject({ code: "invalid_permission" });
    await expect(saveRole(ownerId, space.id, { name: "Ok", permissions: [] })).rejects.toMatchObject({ code: "duplicate_role" });
    await expect(setMemberAttributes(ownerId, space.id, aliceId, { time: "x" })).rejects.toMatchObject({ status: 400 });
  });
});

describe("the permission audit trail", () => {
  it("records every role change, grant and removal in the organization's log, with who did it", async () => {
    const { ownerId, aliceId, space } = await setup();
    const role = await saveRole(ownerId, space.id, { name: "Viewer", permissions: ["report:read"] });
    const assignment = await assignRole(ownerId, space.id, { roleId: role.id, subjectType: "user", subjectId: aliceId, reason: "Quarter close" });
    await setMemberAttributes(ownerId, space.id, aliceId, { department: "finance" });
    await unassignRole(ownerId, space.id, assignment.id);
    await deleteRole(ownerId, space.id, role.id);
    const events = await IdentityEvent.find({ stream: `org:${space.id}` }).sort({ seq: 1 }).lean();
    expect(events.map((e) => e.action)).toEqual(["authz.role_saved", "authz.assigned", "authz.attributes_set", "authz.unassigned", "authz.role_deleted"]);
    expect(events.every((e) => String(e.actorId) === ownerId)).toBe(true);
    expect(events[1]?.data).toMatchObject({ role: "Viewer", subjectId: aliceId, organizationId: space.id });
  });
});
