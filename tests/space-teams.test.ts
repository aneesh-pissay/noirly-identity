import { describe, expect, it } from "vitest";
import { createSpace, removeMember, setAdminAreas } from "@/lib/spaces/space-service";
import { createTeam, deleteTeam, listTeams, MAX_DEPTH, setTeamMember, teamsOf, updateTeam } from "@/lib/spaces/teams";
import { createTestUser } from "./helpers";

async function setup() {
  const { user: owner } = await createTestUser({ email: "owner@example.com" });
  const { user: alice } = await createTestUser({ email: "alice@example.com" });
  const { user: admin } = await createTestUser({ email: "admin@example.com" });
  const space = await createSpace({ ownerId: String(owner._id), name: "Studio", members: [{ userId: String(alice._id), role: "member" }, { userId: String(admin._id), role: "admin" }] });
  return { ownerId: String(owner._id), aliceId: String(alice._id), adminId: String(admin._id), space };
}

describe("teams", () => {
  it("nest, and membership flows up to every team above", async () => {
    const { ownerId, aliceId, space } = await setup();
    const design = await createTeam(ownerId, space.id, { name: "Design" });
    const brand = await createTeam(ownerId, space.id, { name: "Brand", parentId: design.id });
    const print = await createTeam(ownerId, space.id, { name: "Print", parentId: brand.id });
    await createTeam(ownerId, space.id, { name: "Sales" });
    await setTeamMember(ownerId, space.id, print.id, aliceId, true);

    expect(await teamsOf(space.id, aliceId)).toEqual([
      { id: brand.id, name: "Brand", direct: false },
      { id: design.id, name: "Design", direct: false },
      { id: print.id, name: "Print", direct: true },
    ]);
    expect((await listTeams(aliceId, space.id)).map((t) => t.name)).toEqual(["Brand", "Design", "Print", "Sales"]);
  });

  it("can't go inside themselves, nor deeper than the limit", async () => {
    const { ownerId, space } = await setup();
    const a = await createTeam(ownerId, space.id, { name: "A" });
    const b = await createTeam(ownerId, space.id, { name: "B", parentId: a.id });
    await expect(updateTeam(ownerId, space.id, a.id, { parentId: b.id })).rejects.toMatchObject({ code: "cycle" });
    await expect(updateTeam(ownerId, space.id, a.id, { parentId: a.id })).rejects.toMatchObject({ code: "cycle" });

    let parent = b.id;
    for (let depth = 3; depth <= MAX_DEPTH; depth += 1) parent = (await createTeam(ownerId, space.id, { name: `L${depth}`, parentId: parent })).id;
    await expect(createTeam(ownerId, space.id, { name: "Too deep", parentId: parent })).rejects.toMatchObject({ code: "too_deep" });
    // Moving a subtree under something that would make it too deep is refused too.
    const other = await createTeam(ownerId, space.id, { name: "Other" });
    await expect(updateTeam(ownerId, space.id, a.id, { parentId: other.id })).rejects.toMatchObject({ code: "too_deep" });
    await expect(createTeam(ownerId, space.id, { name: "B", parentId: a.id })).rejects.toMatchObject({ code: "duplicate_team" });
  });

  it("move sub-teams up when deleted, and lose members who leave the space", async () => {
    const { ownerId, aliceId, space } = await setup();
    const design = await createTeam(ownerId, space.id, { name: "Design" });
    const brand = await createTeam(ownerId, space.id, { name: "Brand", parentId: design.id });
    await setTeamMember(ownerId, space.id, brand.id, aliceId, true);
    await deleteTeam(ownerId, space.id, design.id);
    expect((await listTeams(ownerId, space.id)).find((t) => t.id === brand.id)?.parentId).toBeNull();

    await removeMember(aliceId, space.id, aliceId);
    expect((await listTeams(ownerId, space.id)).find((t) => t.id === brand.id)?.memberIds).toEqual([]);
  });

  it("take only people in the space, and are managed by admins with the members area", async () => {
    const { ownerId, adminId, aliceId, space } = await setup();
    const team = await createTeam(adminId, space.id, { name: "Ops" });
    const { user: outsider } = await createTestUser({ email: "out@example.com" });
    await expect(setTeamMember(ownerId, space.id, team.id, String(outsider._id), true)).rejects.toMatchObject({ code: "not_in_space" });
    await expect(createTeam(aliceId, space.id, { name: "Mine" })).rejects.toMatchObject({ status: 403 });
    await setAdminAreas(ownerId, space.id, adminId, ["settings"]);
    await expect(createTeam(adminId, space.id, { name: "Nope" })).rejects.toMatchObject({ status: 403 });
    await expect(listTeams(String(outsider._id), space.id)).rejects.toMatchObject({ status: 404 });
  });
});
