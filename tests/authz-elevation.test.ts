import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { saveRole } from "@/lib/authz/admin";
import { cancelRequest, decideRequest, listRequests, requestElevation, sweepExpiredElevations } from "@/lib/authz/elevation";
import { can, explain } from "@/lib/authz/engine";
import { resetEmailProvider, setEmailProvider, type EmailMessage } from "@/lib/email/email-service";
import { createSpace } from "@/lib/spaces/space-service";
import { RoleAssignment } from "@/models/Authz";
import { IdentityEvent } from "@/models/IdentityEvent";
import { createTestUser } from "./helpers";

let sent: EmailMessage[] = [];
beforeEach(() => { sent = []; setEmailProvider({ send: async (m) => { sent.push(m); } }); });
afterEach(() => resetEmailProvider());

async function setup() {
  const { user: owner } = await createTestUser({ email: "owner@example.com" });
  const { user: alice } = await createTestUser({ email: "alice@example.com" });
  const ownerId = String(owner._id);
  const aliceId = String(alice._id);
  const space = await createSpace({ ownerId, name: "Ops", members: [{ userId: aliceId, role: "member" }] });
  const role = await saveRole(ownerId, space.id, { name: "Production access", permissions: ["prod:*"] });
  return { ownerId, aliceId, space, role };
}
const alice = (id: string) => ({ type: "user" as const, id });

describe("short-lived elevated access", () => {
  it("is asked for with a reason, approved by an admin, and ends by itself", async () => {
    const { ownerId, aliceId, space, role } = await setup();
    const request = await requestElevation(aliceId, space.id, { roleId: role.id, reason: "Fixing incident 42", durationMinutes: 30 });
    expect(request).toMatchObject({ status: "pending", role: "Production access", durationMinutes: 30 });
    // The admin hears about it.
    expect(sent.map((m) => m.to)).toEqual(["owner@example.com"]);
    expect(await can(space.id, alice(aliceId), "prod:deploy")).toBe(false);

    const approved = await decideRequest(ownerId, space.id, request.id, true);
    expect(approved.status).toBe("approved");
    expect(new Date(approved.expiresAt!).getTime() - Date.now()).toBeGreaterThan(29 * 60_000);
    expect(sent.at(-1)).toMatchObject({ to: "alice@example.com" });
    expect(await can(space.id, alice(aliceId), "prod:deploy")).toBe(true);
    // Half an hour later it no longer counts, sweep or not.
    expect((await explain(space.id, alice(aliceId), "prod:deploy", null, { now: new Date(Date.now() + 31 * 60_000) })).allowed).toBe(false);

    expect(await sweepExpiredElevations(new Date(Date.now() + 31 * 60_000))).toBe(1);
    expect(await RoleAssignment.countDocuments({})).toBe(0);
    const actions = (await IdentityEvent.find({ stream: `org:${space.id}` }).sort({ seq: 1 }).lean()).map((e) => e.action);
    expect(actions).toEqual(["authz.role_saved", "authz.elevation_requested", "authz.assigned", "authz.elevation_approved", "authz.unassigned"]);
  });

  it("can't be approved by the one asking, nor twice, and can be denied or withdrawn", async () => {
    const { ownerId, aliceId, space, role } = await setup();
    const request = await requestElevation(aliceId, space.id, { roleId: role.id, reason: "Need it now", durationMinutes: 15 });
    await expect(decideRequest(aliceId, space.id, request.id, true)).rejects.toMatchObject({ status: 403 });
    await expect(requestElevation(aliceId, space.id, { roleId: role.id, reason: "Again please", durationMinutes: 15 })).rejects.toMatchObject({ code: "already_requested" });
    await decideRequest(ownerId, space.id, request.id, false);
    await expect(decideRequest(ownerId, space.id, request.id, true)).rejects.toMatchObject({ code: "already_decided" });
    expect(await can(space.id, alice(aliceId), "prod:deploy")).toBe(false);

    const second = await requestElevation(aliceId, space.id, { roleId: role.id, reason: "Different day", durationMinutes: 60 });
    await cancelRequest(aliceId, space.id, second.id);
    expect((await listRequests(aliceId, space.id)).map((r) => r.status)).toEqual(["cancelled", "denied"]);
  });

  it("keeps requests within bounds and shows members only their own", async () => {
    const { ownerId, aliceId, space, role } = await setup();
    await expect(requestElevation(aliceId, space.id, { roleId: role.id, reason: "Long", durationMinutes: 8 * 24 * 60 })).rejects.toMatchObject({ status: 400 });
    await expect(requestElevation(aliceId, space.id, { roleId: role.id, reason: "x", durationMinutes: 30 })).rejects.toMatchObject({ status: 400 });
    const { user: bob } = await createTestUser({ email: "bob@example.com" });
    await expect(requestElevation(String(bob._id), space.id, { roleId: role.id, reason: "Not a member", durationMinutes: 30 })).rejects.toMatchObject({ status: 404 });
    await requestElevation(aliceId, space.id, { roleId: role.id, reason: "Mine only", durationMinutes: 30 });
    expect(await listRequests(ownerId, space.id)).toHaveLength(1);
  });
});
