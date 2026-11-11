import { afterEach, describe, expect, it } from "vitest";
import { addDomain, joinableSpaces, joinThroughDomain, listDomains, normalizeDomain, removeDomain, setDomainPolicy, setTxtResolver, verifyDomain } from "@/lib/spaces/domains";
import { createSpace, getSpace } from "@/lib/spaces/space-service";
import { UserEmail } from "@/models/UserEmail";
import { createTestUser } from "./helpers";

const records = new Map<string, string[][]>();
setTxtResolver(async (name) => {
  const found = records.get(name);
  if (!found) throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
  return found;
});
afterEach(() => records.clear());

async function setup() {
  const { user: owner } = await createTestUser({ email: "owner@acme.example" });
  const space = await createSpace({ ownerId: String(owner._id), name: "Acme" });
  return { ownerId: String(owner._id), space };
}

describe("verified business domains", () => {
  it("are proven by a TXT record, then claimed by that space alone", async () => {
    const { ownerId, space } = await setup();
    const added = await addDomain(ownerId, space.id, "ACME.example.");
    expect(added).toMatchObject({ domain: "acme.example", verified: false, txtName: "_noirly-verify.acme.example" });
    expect(added.txtValue).toMatch(/^noirly-verification=/);

    await expect(verifyDomain(ownerId, space.id, "acme.example")).rejects.toMatchObject({ code: "not_verified" });
    records.set("_noirly-verify.acme.example", [["v=spf1 -all"], ["noirly-verif", `ication=${added.txtValue.split("=")[1]}`]]);
    expect(await verifyDomain(ownerId, space.id, "acme.example")).toMatchObject({ verified: true });

    // Nobody else can take it now.
    const { user: rival } = await createTestUser({ email: "rival@other.example" });
    const theirs = await createSpace({ ownerId: String(rival._id), name: "Rival" });
    await expect(addDomain(String(rival._id), theirs.id, "acme.example")).rejects.toMatchObject({ code: "domain_taken" });
  });

  it("refuse personal email providers and things that aren't domains", () => {
    expect(() => normalizeDomain("gmail.com")).toThrow(/personal/);
    expect(() => normalizeDomain("not a domain")).toThrow(/domain/);
    expect(normalizeDomain(" Sub.Acme.Example ")).toBe("sub.acme.example");
  });

  it("let people with a confirmed address there join, once the policy allows it", async () => {
    const { ownerId, space } = await setup();
    const added = await addDomain(ownerId, space.id, "acme.example");
    await expect(setDomainPolicy(ownerId, space.id, "acme.example", "auto_join")).rejects.toMatchObject({ code: "not_verified" });
    records.set("_noirly-verify.acme.example", [[added.txtValue]]);
    await verifyDomain(ownerId, space.id, "acme.example");

    const { user: colleague } = await createTestUser({ email: "colleague@acme.example" });
    const { user: outsider } = await createTestUser({ email: "someone@else.example" });
    // Invite-only by default: not joinable.
    expect(await joinableSpaces(String(colleague._id))).toEqual([]);
    await setDomainPolicy(ownerId, space.id, "acme.example", "auto_join");
    expect(await joinableSpaces(String(colleague._id))).toEqual([{ id: space.id, name: "Acme", domain: "acme.example" }]);
    expect(await joinableSpaces(String(outsider._id))).toEqual([]);
    await expect(joinThroughDomain(String(outsider._id), space.id)).rejects.toMatchObject({ status: 404 });

    await joinThroughDomain(String(colleague._id), space.id);
    expect((await getSpace(space.id)).members.find((m) => m.email === "colleague@acme.example")?.role).toBe("member");
    expect(await joinableSpaces(String(colleague._id))).toEqual([]);

    // A confirmed extra address counts; an unconfirmed one doesn't.
    await UserEmail.create({ userId: outsider._id, email: "pending@acme.example", verifiedAt: null });
    expect(await joinableSpaces(String(outsider._id))).toEqual([]);
    await UserEmail.updateOne({ email: "pending@acme.example" }, { $set: { verifiedAt: new Date() } });
    expect(await joinableSpaces(String(outsider._id))).toHaveLength(1);
  });

  it("are managed by owners only", async () => {
    const { ownerId, space } = await setup();
    await addDomain(ownerId, space.id, "acme.example");
    const { user: member } = await createTestUser({ email: "member@acme.example" });
    const { OrganizationMembership } = await import("@/models/OrganizationMembership");
    await OrganizationMembership.create({ organizationId: space.id, userId: member._id, role: "admin" });
    await expect(addDomain(String(member._id), space.id, "other.example")).rejects.toMatchObject({ status: 403 });
    expect((await listDomains(String(member._id), space.id)).map((d) => d.domain)).toEqual(["acme.example"]);
    await removeDomain(ownerId, space.id, "acme.example");
    expect(await listDomains(ownerId, space.id)).toEqual([]);
  });
});
