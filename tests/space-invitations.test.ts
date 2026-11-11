import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { POST as inviteRoute } from "@/app/api/spaces/[spaceId]/members/route";
import { GET as previewRoute, POST as acceptRoute } from "@/app/api/invitations/route";
import { getEnv } from "@/lib/config/env";
import { resetEmailProvider, setEmailProvider, type EmailMessage } from "@/lib/email/email-service";
import { createSession } from "@/lib/sessions/session-service";
import { acceptInvitation, inviteToSpace, listInvitations, previewInvitation, revokeInvitation } from "@/lib/spaces/invitations";
import { createSpace, getSpace } from "@/lib/spaces/space-service";
import { SpaceInvitation } from "@/models/SpaceInvitation";
import { UserEmail } from "@/models/UserEmail";
import { createTestUser } from "./helpers";

const jar = vi.hoisted(() => new Map<string, string>());
vi.mock("next/headers", () => ({ cookies: async () => ({ get: (key: string) => (jar.has(key) ? { value: jar.get(key) } : undefined) }) }));

let sent: EmailMessage[] = [];
beforeEach(() => {
  jar.clear();
  sent = [];
  setEmailProvider({ send: async (message) => { sent.push(message); } });
});
afterEach(() => resetEmailProvider());

const tokenFrom = (message: EmailMessage) => new URL(message.text.match(/https?:\/\/\S+/)![0]).searchParams.get("token")!;

async function setup() {
  const { user: owner } = await createTestUser({ email: "owner@example.com" });
  const space = await createSpace({ ownerId: String(owner._id), name: "Studio" });
  return { owner, ownerId: String(owner._id), space };
}

describe("space invitations", () => {
  it("email a week-long link, and the person with that address joins with the invited role", async () => {
    const { ownerId, space } = await setup();
    const { invitation } = await inviteToSpace(ownerId, space.id, "New.Person@Example.com", "admin");
    expect(invitation).toMatchObject({ email: "new.person@example.com", role: "admin" });
    expect(new Date(invitation.expiresAt).getTime() - Date.now()).toBeGreaterThan(6.9 * 86_400_000);
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({ to: "new.person@example.com", subject: "Join Studio on Noirly" });
    const token = tokenFrom(sent[0]!);
    // Only the hash is kept.
    expect(await SpaceInvitation.exists({ tokenHash: token })).toBeNull();

    expect(await previewInvitation(token)).toEqual({ space: "Studio", role: "admin", email: "new.person@example.com" });
    const { user: invitee } = await createTestUser({ email: "new.person@example.com" });
    await acceptInvitation(String(invitee._id), token);
    expect((await getSpace(space.id)).members.find((m) => m.email === "new.person@example.com")?.role).toBe("admin");
    // Used once.
    await expect(acceptInvitation(String(invitee._id), token)).rejects.toMatchObject({ status: 410 });
    expect(await listInvitations(ownerId, space.id)).toEqual([]);
  });

  it("only let in an account that owns the address, a confirmed extra address included", async () => {
    const { ownerId, space } = await setup();
    await inviteToSpace(ownerId, space.id, "invited@example.com", "member");
    const token = tokenFrom(sent[0]!);
    const { user: someoneElse } = await createTestUser({ email: "forwarded-to@example.com" });
    await expect(acceptInvitation(String(someoneElse._id), token)).rejects.toMatchObject({ code: "wrong_account" });
    await UserEmail.create({ userId: someoneElse._id, email: "invited@example.com", verifiedAt: new Date() });
    await acceptInvitation(String(someoneElse._id), token);
    expect((await getSpace(space.id)).members.map((m) => m.email)).toContain("forwarded-to@example.com");
  });

  it("expire, can be withdrawn, and a newer one replaces an older one", async () => {
    const { ownerId, space } = await setup();
    const { user: invitee } = await createTestUser({ email: "late@example.com" });
    await inviteToSpace(ownerId, space.id, "late@example.com", "member");
    const first = tokenFrom(sent[0]!);
    await inviteToSpace(ownerId, space.id, "late@example.com", "member");
    const second = tokenFrom(sent[1]!);
    await expect(acceptInvitation(String(invitee._id), first)).rejects.toMatchObject({ status: 410 });
    const [pending] = await listInvitations(ownerId, space.id);
    await revokeInvitation(ownerId, space.id, pending!.id);
    await expect(previewInvitation(second)).rejects.toMatchObject({ code: "invitation_gone" });

    await inviteToSpace(ownerId, space.id, "late@example.com", "member");
    const third = tokenFrom(sent[2]!);
    await SpaceInvitation.updateMany({}, { $set: { expiresAt: new Date(Date.now() - 1000) } });
    await expect(acceptInvitation(String(invitee._id), third)).rejects.toMatchObject({ status: 410 });
  });

  it("are for admins to send, owners only by owners, and not to existing members", async () => {
    const { ownerId, space } = await setup();
    const { user: member } = await createTestUser({ email: "member@example.com" });
    await inviteToSpace(ownerId, space.id, "member@example.com", "member");
    await acceptInvitation(String(member._id), tokenFrom(sent[0]!));
    await expect(inviteToSpace(String(member._id), space.id, "x@example.com", "member")).rejects.toMatchObject({ status: 403 });
    await expect(inviteToSpace(ownerId, space.id, "member@example.com", "member")).rejects.toMatchObject({ code: "already_member" });
    const { user: admin } = await createTestUser({ email: "admin@example.com" });
    await inviteToSpace(ownerId, space.id, "admin@example.com", "admin");
    await acceptInvitation(String(admin._id), tokenFrom(sent[1]!));
    await expect(inviteToSpace(String(admin._id), space.id, "boss@example.com", "owner")).rejects.toMatchObject({ status: 403 });
  });

  it("work through the routes: invite, preview, then join signed in", async () => {
    const { owner, space } = await setup();
    const sign = async (userId: unknown) => {
      const { token } = await createSession({ userId: String(userId) });
      jar.clear();
      jar.set(getEnv().SESSION_COOKIE_NAME, token);
      jar.set(getEnv().CSRF_COOKIE_NAME, "csrf");
    };
    const json = (url: string, body: unknown) => new NextRequest(url, { method: "POST", headers: { "content-type": "application/json", "x-csrf-token": "csrf", origin: "http://localhost:3000" }, body: JSON.stringify(body) });
    await sign(owner._id);
    const invited = await inviteRoute(json(`http://localhost:3000/api/spaces/${space.id}/members`, { email: "route@example.com" }), { params: Promise.resolve({ spaceId: space.id }) });
    expect(invited.status).toBe(201);
    const token = tokenFrom(sent[0]!);
    expect((await (await previewRoute(new NextRequest(`http://localhost:3000/api/invitations?token=${token}`))).json()).invitation.space).toBe("Studio");

    // Not signed in: 401, so the page offers sign-in.
    jar.clear();
    jar.set(getEnv().CSRF_COOKIE_NAME, "csrf");
    expect((await acceptRoute(json("http://localhost:3000/api/invitations", { token }))).status).toBe(401);
    const { user: invitee } = await createTestUser({ email: "route@example.com" });
    await sign(invitee._id);
    expect(await (await acceptRoute(json("http://localhost:3000/api/invitations", { token }))).json()).toEqual({ spaceId: space.id });
  });
});
