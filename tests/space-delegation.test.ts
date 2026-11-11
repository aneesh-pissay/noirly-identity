import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resetEmailProvider, setEmailProvider } from "@/lib/email/email-service";
import { addDomain } from "@/lib/spaces/domains";
import { inviteToSpace } from "@/lib/spaces/invitations";
import { addMemberByEmail, canAdminister, createSpace, getSpace, renameSpace, setAdminAreas, transferOwnership } from "@/lib/spaces/space-service";
import { createTestUser } from "./helpers";

beforeEach(() => setEmailProvider({ send: async () => undefined }));
afterEach(() => resetEmailProvider());

async function setup() {
  const { user: owner } = await createTestUser({ email: "owner@example.com" });
  const { user: admin } = await createTestUser({ email: "admin@example.com" });
  const { user: member } = await createTestUser({ email: "member@example.com" });
  const space = await createSpace({ ownerId: String(owner._id), name: "Studio", members: [{ userId: String(admin._id), role: "admin" }, { userId: String(member._id), role: "member" }] });
  return { ownerId: String(owner._id), adminId: String(admin._id), memberId: String(member._id), space };
}

describe("ownership transfer", () => {
  it("makes the other member an owner and the old owner an admin, in one step", async () => {
    const { ownerId, memberId, space } = await setup();
    const after = await transferOwnership(ownerId, space.id, memberId);
    const roles = Object.fromEntries(after.members.map((m) => [m.email, m.role]));
    expect(roles).toMatchObject({ "owner@example.com": "admin", "member@example.com": "owner" });
    // Only owners can, and not to themselves or outsiders.
    await expect(transferOwnership(ownerId, space.id, memberId)).rejects.toMatchObject({ status: 403 });
    await expect(transferOwnership(memberId, space.id, memberId)).rejects.toMatchObject({ status: 400 });
    const { user: outsider } = await createTestUser({ email: "out@example.com" });
    await expect(transferOwnership(memberId, space.id, String(outsider._id))).rejects.toMatchObject({ status: 404 });
  });
});

describe("delegated administration", () => {
  it("limits an admin to the areas the owner chooses, and lifts the limit again", async () => {
    const { ownerId, adminId, space } = await setup();
    // Unlimited by default: members and settings.
    expect(await canAdminister(space.id, adminId, "members")).toBe(true);
    await renameSpace(adminId, space.id, "Studio One");

    const limited = await setAdminAreas(ownerId, space.id, adminId, ["members"]);
    expect(limited.members.find((m) => m.email === "admin@example.com")?.adminAreas).toEqual(["members"]);
    await expect(renameSpace(adminId, space.id, "Mine")).rejects.toMatchObject({ status: 403 });
    await inviteToSpace(adminId, space.id, "new@example.com", "member");

    await setAdminAreas(ownerId, space.id, adminId, ["settings"]);
    await expect(inviteToSpace(adminId, space.id, "other@example.com", "member")).rejects.toMatchObject({ status: 403 });
    await expect(addMemberByEmail(adminId, space.id, "member@example.com", "member")).rejects.toMatchObject({ status: 403 });
    await renameSpace(adminId, space.id, "Studio Two");

    await setAdminAreas(ownerId, space.id, adminId, null);
    expect((await getSpace(space.id)).members.find((m) => m.email === "admin@example.com")?.adminAreas).toBeUndefined();
  });

  it("gives domains to admins only when delegated, and is set by owners for admins only", async () => {
    const { ownerId, adminId, memberId, space } = await setup();
    await expect(addDomain(adminId, space.id, "studio.example")).rejects.toMatchObject({ status: 403 });
    await setAdminAreas(ownerId, space.id, adminId, ["domains"]);
    expect(await addDomain(adminId, space.id, "studio.example")).toMatchObject({ domain: "studio.example" });

    await expect(setAdminAreas(adminId, space.id, adminId, null)).rejects.toMatchObject({ status: 403 });
    await expect(setAdminAreas(ownerId, space.id, memberId, ["members"])).rejects.toMatchObject({ code: "not_admin" });
    // Handing over clears any limits on the new owner.
    await setAdminAreas(ownerId, space.id, adminId, ["members"]);
    const after = await transferOwnership(ownerId, space.id, adminId);
    expect(after.members.find((m) => m.email === "admin@example.com")).toMatchObject({ role: "owner" });
    expect(after.members.find((m) => m.email === "admin@example.com")?.adminAreas).toBeUndefined();
  });
});
