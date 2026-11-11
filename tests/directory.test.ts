import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Types } from "mongoose";
import { bulkInvite, bulkManage, importCsv, parseCsv } from "@/lib/directory/bulk";
import { deactivateMember, listDeactivated, reactivateMember } from "@/lib/directory/lifecycle";
import { directoryReport, linkDirectoryId } from "@/lib/directory/reconcile";
import { resetEmailProvider, setEmailProvider, type EmailMessage } from "@/lib/email/email-service";
import { createSession } from "@/lib/sessions/session-service";
import { acceptInvitation } from "@/lib/spaces/invitations";
import { createSpace } from "@/lib/spaces/space-service";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { Session } from "@/models/Session";
import { SpaceDomain } from "@/models/SpaceDomain";
import { SpaceTeam } from "@/models/SpaceTeam";
import { User } from "@/models/User";
import { UserEmail } from "@/models/UserEmail";
import { createTestUser } from "./helpers";

let sent: EmailMessage[] = [];
beforeEach(() => { sent = []; setEmailProvider({ send: async (m) => { sent.push(m); } }); });
afterEach(() => resetEmailProvider());

async function setup() {
  const { user: owner } = await createTestUser({ email: "owner@acme.test" });
  const space = await createSpace({ ownerId: String(owner._id), name: "Acme" });
  await SpaceDomain.create({ organizationId: new Types.ObjectId(space.id), domain: "acme.test", verificationToken: "t", verifiedAt: new Date() });
  return { owner, space, ownerId: String(owner._id) };
}

const join = (spaceId: string, userId: Types.ObjectId, role: "member" | "admin" | "owner" = "member") => OrganizationMembership.create({ organizationId: new Types.ObjectId(spaceId), userId, role });

describe("bulk invitation and CSV import", () => {
  it("invites many, reports each row, and applies CSV teams on acceptance", async () => {
    const { space, ownerId } = await setup();
    const invited = await bulkInvite(ownerId, space.id, ["a@acme.test", "not-an-email", "b@acme.test", "a@acme.test"], "member");
    expect(invited.map((r) => r.ok)).toEqual([true, false, true]);
    expect(sent.filter((m) => m.to === "a@acme.test")).toHaveLength(1);

    await SpaceTeam.create({ organizationId: new Types.ObjectId(space.id), name: "Finance" });
    const csv = 'email,role,teams\r\n"carol@acme.test",admin,Finance\ndave@acme.test,,\nerin@acme.test,boss,\nfrank@acme.test,member,Nope\n';
    const results = await importCsv(ownerId, space.id, csv);
    expect(results.map((r) => [r.row, r.ok])).toEqual([[2, true], [3, true], [4, false], [5, false]]);
    expect(results[2]!.result).toContain("Unknown role");

    const { user: carol } = await createTestUser({ email: "carol@acme.test" });
    const link = sent.find((m) => m.to === "carol@acme.test")!.text.match(/token=([\w-]+)/)![1]!;
    await acceptInvitation(String(carol._id), link);
    expect((await OrganizationMembership.findOne({ organizationId: new Types.ObjectId(space.id), userId: carol._id }).lean())?.role).toBe("admin");
    expect((await SpaceTeam.findOne({ name: "Finance" }).lean())?.memberIds.map(String)).toEqual([String(carol._id)]);
  });

  it("parses quoted CSV", () => {
    expect(parseCsv('a,"b, c","d ""e"""\n1,2,3')).toEqual([["a", "b, c", 'd "e"'], ["1", "2", "3"]]);
  });
});

describe("offboarding, reactivation and bulk management", () => {
  it("locks an owned identity everywhere, but only removes an outside member from the space", async () => {
    const { space, ownerId } = await setup();
    const { user: inside } = await createTestUser({ email: "in@acme.test" });
    const { user: outside } = await createTestUser({ email: "out@elsewhere.test" });
    await join(space.id, inside._id);
    await join(space.id, outside._id, "admin");
    const team = await SpaceTeam.create({ organizationId: new Types.ObjectId(space.id), name: "Ops", memberIds: [inside._id, outside._id] });
    await createSession({ userId: String(inside._id), methods: ["password"] });
    await createSession({ userId: String(outside._id), methods: ["password"] });

    const results = await bulkManage(ownerId, space.id, [String(inside._id), String(outside._id), ownerId], { action: "deactivate" });
    expect(results.map((r) => r.ok)).toEqual([true, true, false]);
    expect((await User.findById(inside._id).lean())?.lockKind).toBe("deprovisioned");
    expect(await Session.countDocuments({ userId: inside._id, revokedAt: null })).toBe(0);
    expect((await User.findById(outside._id).lean())?.lockedAt).toBeNull();
    expect(await Session.countDocuments({ userId: outside._id, revokedAt: null })).toBe(1);
    expect((await SpaceTeam.findById(team._id).lean())?.memberIds).toEqual([]);
    expect((await listDeactivated(ownerId, space.id)).map((d) => [d.email, d.accountLocked])).toEqual(expect.arrayContaining([["in@acme.test", true], ["out@elsewhere.test", false]]));

    // Reactivation puts back the role, the teams and (for the owned identity) the account.
    await reactivateMember(space.id, String(outside._id), { actorId: ownerId, via: "admin" });
    expect((await OrganizationMembership.findOne({ userId: outside._id }).lean())?.role).toBe("admin");
    const back = await reactivateMember(space.id, String(inside._id), { actorId: ownerId, via: "admin" });
    expect(back.accountUnlocked).toBe(true);
    expect((await User.findById(inside._id).lean())?.lockedAt).toBeNull();
    expect((await SpaceTeam.findById(team._id).lean())?.memberIds.map(String).sort()).toEqual([String(inside._id), String(outside._id)].sort());

    // Owners can't be deactivated; an unknown team is refused before anything changes.
    await expect(deactivateMember(space.id, ownerId, { actorId: null, via: "admin" })).rejects.toMatchObject({ code: "owner" });
    await expect(bulkManage(ownerId, space.id, [String(inside._id)], { action: "add_to_team", teamId: String(new Types.ObjectId()) })).rejects.toMatchObject({ code: "not_found" });
  });
});

describe("reconciliation", () => {
  it("finds duplicates, unmanaged and outside members, and links directory ids", async () => {
    const { space, ownerId } = await setup();
    const { user: ann } = await createTestUser({ email: "ann@acme.test" });
    await createTestUser({ email: "ann+old@acme.test" });
    const { user: other } = await createTestUser({ email: "ann.personal@example.com" });
    await UserEmail.create({ userId: other._id, email: "ann2@acme.test", verifiedAt: new Date() });
    await createTestUser({ email: "ann2@acme.test" });
    const { user: guest } = await createTestUser({ email: "guest@partner.test" });
    await join(space.id, ann._id);
    await join(space.id, guest._id);

    const report = await directoryReport(ownerId, space.id);
    expect(report.duplicates.map((d) => [d.key, d.reason])).toEqual(expect.arrayContaining([["ann@acme.test", "plus_alias"], ["ann2@acme.test", "additional_address"]]));
    expect(report.unmanaged.map((m) => m.email).sort()).toEqual(["ann@acme.test", "owner@acme.test"]);
    expect(report.outside.map((m) => m.email)).toEqual(["guest@partner.test"]);

    await linkDirectoryId(ownerId, space.id, String(ann._id), "entra-ann");
    expect((await directoryReport(ownerId, space.id)).unmanaged.map((m) => m.email)).toEqual(["owner@acme.test"]);
    await expect(linkDirectoryId(ownerId, space.id, ownerId, "entra-ann")).rejects.toMatchObject({ status: 409 });
  });
});
