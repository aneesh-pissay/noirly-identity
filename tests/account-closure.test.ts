import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { closeAccount, CLOSURE_GRACE_DAYS, exportIdentityData, sweepClosedAccounts, undoClosure } from "@/lib/account/closure";
import { loginUser } from "@/lib/auth/auth-service";
import { resetEmailProvider, setEmailProvider, type EmailMessage } from "@/lib/email/email-service";
import { createSession, validateSession } from "@/lib/sessions/session-service";
import { createSpace } from "@/lib/spaces/space-service";
import { issueAccessToken, resolveAccessToken } from "@/lib/tokens/token-service";
import { User } from "@/models/User";
import { UserEmail } from "@/models/UserEmail";
import { createTestClient, createTestUser } from "./helpers";

let sent: EmailMessage[] = [];
beforeEach(() => { sent = []; setEmailProvider({ send: async (m) => { sent.push(m); } }); });
afterEach(() => resetEmailProvider());

const undoToken = (m: EmailMessage) => new URL(m.text.match(/https?:\/\/\S+\/close-account\/undo\?token=\S+/)![0]).searchParams.get("token")!;

describe("closing an account", () => {
  it("signs out and revokes everywhere at once, tells every address, and deletes after the grace period", async () => {
    const { user, password } = await createTestUser({ email: "owner@example.com" });
    const id = String(user._id);
    await UserEmail.create({ userId: user._id, email: "work@example.com", verifiedAt: new Date() });
    const { client } = await createTestClient();
    const { token, session } = await createSession({ userId: id });
    const access = await issueAccessToken({ clientId: client.clientId, userId: id, sessionId: session._id, scope: "openid" });

    const { deleteAfter } = await closeAccount(id);
    expect(Math.round((new Date(deleteAfter).getTime() - Date.now()) / 86_400_000)).toBe(CLOSURE_GRACE_DAYS);
    expect(await validateSession(token)).toBeNull();
    expect(await resolveAccessToken(access.token)).toBeNull();
    await expect(loginUser({ email: user.email, password } as never, {})).rejects.toMatchObject({ status: 401 });
    expect(sent.map((m) => m.to).sort()).toEqual(["owner@example.com", "work@example.com"]);

    // Not yet: still there.
    expect(await sweepClosedAccounts()).toBe(0);
    expect(await User.countDocuments({ _id: id })).toBe(1);
    // After the grace period: gone.
    expect(await sweepClosedAccounts(new Date(Date.now() + (CLOSURE_GRACE_DAYS + 1) * 86_400_000))).toBe(1);
    expect(await User.countDocuments({ _id: id })).toBe(0);
  });

  it("can be undone from the email within the grace period", async () => {
    const { user, password } = await createTestUser({ email: "owner@example.com" });
    await closeAccount(String(user._id));
    await undoClosure(undoToken(sent[0]!));
    expect(await User.findById(user._id).lean()).toMatchObject({ lockedAt: null, closingAt: null, deleteAfter: null });
    await expect(loginUser({ email: user.email, password } as never, {})).resolves.toBeTruthy();
    expect(await sweepClosedAccounts(new Date(Date.now() + 30 * 86_400_000))).toBe(0);
    await expect(undoClosure(undoToken(sent[0]!))).rejects.toMatchObject({ code: "invalid_token" });
  });
});

describe("exporting Identity's data", () => {
  it("includes the profile, addresses, sessions, spaces and activity, and no secrets", async () => {
    const { user } = await createTestUser({ email: "owner@example.com" });
    const id = String(user._id);
    await createSpace({ ownerId: id, name: "Studio" });
    await createSession({ userId: id, place: "Pune, IN" });
    const data = await exportIdentityData(id);
    expect(data.account).toMatchObject({ id, email: "owner@example.com" });
    expect(data.spaces).toEqual([expect.objectContaining({ space: "Studio", role: "owner" })]);
    expect(data.sessions).toHaveLength(1);
    const text = JSON.stringify(data);
    expect(text).not.toContain("passwordHash");
    expect(text).not.toContain("tokenHash");
  });
});
