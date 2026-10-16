import { describe, expect, it } from "vitest";
import { NextRequest } from "next/server";
import {
  addMemberByEmail,
  changeMemberRole,
  createSpace,
  deleteSpace,
  getSpaceForMember,
  handOverOwnedSpaces,
  listSpacesForUser,
  removeMember,
} from "@/lib/spaces/space-service";
import { requireSpacesClient } from "@/lib/spaces/integration-auth";
import { OAuthClient } from "@/models/OAuthClient";
import { createTestClient, createTestUser } from "./helpers";

async function people() {
  const { user: owner } = await createTestUser({ email: "owner@example.com" });
  const { user: admin } = await createTestUser({ email: "admin@example.com" });
  const { user: member } = await createTestUser({ email: "member@example.com" });
  const { user: unverified } = await createTestUser({ email: "pending@example.com", status: "pending_verification" });
  const space = await createSpace({ ownerId: String(owner._id), name: "Goa Trip" });
  await addMemberByEmail(String(owner._id), space.id, "admin@example.com", "admin");
  await addMemberByEmail(String(owner._id), space.id, "member@example.com", "member");
  return { owner: String(owner._id), admin: String(admin._id), member: String(member._id), unverified, space };
}

describe("spaces", () => {
  it("creates a space owned by its creator and lists it with roles", async () => {
    const { owner, member, space } = await people();
    expect((await listSpacesForUser(owner))[0]).toMatchObject({ id: space.id, role: "owner", memberCount: 3 });
    expect((await listSpacesForUser(member))[0]).toMatchObject({ role: "member" });
    const seen = await getSpaceForMember(space.id, member);
    expect(seen.members.map((m) => m.role)).toEqual(["owner", "admin", "member"]);
  });

  it("only adds verified accounts, once, by admins", async () => {
    const { admin, member, space } = await people();
    await expect(addMemberByEmail(admin, space.id, "pending@example.com", "member")).rejects.toMatchObject({ status: 404 });
    await expect(addMemberByEmail(admin, space.id, "nobody@example.com", "member")).rejects.toMatchObject({ status: 404 });
    await expect(addMemberByEmail(admin, space.id, "member@example.com", "member")).rejects.toMatchObject({ code: "already_member" });
    await createTestUser({ email: "new@example.com" });
    await expect(addMemberByEmail(member, space.id, "new@example.com", "member")).rejects.toMatchObject({ status: 403 });
    // Admins can't hand out ownership.
    await expect(addMemberByEmail(admin, space.id, "new@example.com", "owner")).rejects.toMatchObject({ status: 403 });
  });

  it("hides spaces from outsiders", async () => {
    const { space } = await people();
    const { user: outsider } = await createTestUser({ email: "outsider@example.com" });
    await expect(getSpaceForMember(space.id, String(outsider._id))).rejects.toMatchObject({ status: 404 });
  });

  it("keeps at least one owner, and only owners manage owners", async () => {
    const { owner, admin, member, space } = await people();
    await expect(changeMemberRole(owner, space.id, owner, "member")).rejects.toMatchObject({ code: "last_owner" });
    await expect(removeMember(owner, space.id, owner)).rejects.toMatchObject({ code: "last_owner" });
    await expect(changeMemberRole(admin, space.id, member, "owner")).rejects.toMatchObject({ status: 403 });
    await expect(removeMember(admin, space.id, owner)).rejects.toMatchObject({ status: 403 });
    // With a second owner, the first can step down.
    await changeMemberRole(owner, space.id, admin, "owner");
    await changeMemberRole(owner, space.id, owner, "member");
  });

  it("lets anyone leave, and admins remove members", async () => {
    const { admin, member, space } = await people();
    await removeMember(member, space.id, member);
    expect((await listSpacesForUser(member)).length).toBe(0);
    await expect(removeMember(member, space.id, admin)).rejects.toMatchObject({ status: 404 });
  });

  it("deletes spaces for owners only", async () => {
    const { owner, admin, space } = await people();
    await expect(deleteSpace(admin, space.id)).rejects.toMatchObject({ status: 403 });
    await deleteSpace(owner, space.id);
    expect((await listSpacesForUser(owner)).length).toBe(0);
  });

  it("hands a sole owner's spaces to an admin before the account goes", async () => {
    const { owner, admin, space } = await people();
    const { Types } = await import("mongoose");
    await handOverOwnedSpaces(new Types.ObjectId(owner));
    const seen = await getSpaceForMember(space.id, admin);
    expect(seen.role).toBe("owner");
  });
});

describe("integration access", () => {
  function basic(clientId: string, secret: string) {
    return new NextRequest("http://localhost/api/integrations/spaces", {
      headers: { authorization: `Basic ${Buffer.from(`${clientId}:${secret}`).toString("base64")}` },
    });
  }

  it("needs a confidential client granted the organizations scope", async () => {
    const { client, clientSecret } = await createTestClient();
    await expect(requireSpacesClient(basic(client.clientId, clientSecret))).rejects.toMatchObject({ status: 403 });
    await OAuthClient.updateOne({ _id: client._id }, { $addToSet: { allowedScopes: "organizations" } });
    await expect(requireSpacesClient(basic(client.clientId, clientSecret))).resolves.toMatchObject({ clientId: client.clientId });
    await expect(requireSpacesClient(basic(client.clientId, "wrong-secret"))).rejects.toBeTruthy();
  });
});
