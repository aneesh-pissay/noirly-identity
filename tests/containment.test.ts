import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loginUser, resetUserPassword } from "@/lib/auth/auth-service";
import { resetEmailProvider, setEmailProvider, type EmailMessage } from "@/lib/email/email-service";
import { containAccount, unlockAccount } from "@/lib/security/containment";
import { createSession, validateSession } from "@/lib/sessions/session-service";
import { issueAccessToken, issueRefreshToken, resolveAccessToken } from "@/lib/tokens/token-service";
import { IdentityEvent } from "@/models/IdentityEvent";
import { RefreshToken } from "@/models/RefreshToken";
import { User } from "@/models/User";
import { createTestClient, createTestUser } from "./helpers";

let sent: EmailMessage[] = [];
beforeEach(() => { sent = []; setEmailProvider({ send: async (m) => { sent.push(m); } }); });
afterEach(() => resetEmailProvider());

describe("account takeover containment", () => {
  it("locks, signs out everywhere, revokes app tokens and removes the password, in one action", async () => {
    const { user: admin } = await createTestUser({ email: "admin@example.com" });
    const { user, password } = await createTestUser({ email: "victim@example.com" });
    const { client } = await createTestClient();
    const { token, session } = await createSession({ userId: user._id });
    const access = await issueAccessToken({ clientId: client.clientId, userId: user._id, sessionId: session._id, scope: "openid" });
    await issueRefreshToken({ clientId: client.clientId, userId: user._id, sessionId: session._id, scope: "openid offline_access" });

    const result = await containAccount(String(admin._id), { email: "Victim@Example.com" }, "Logins from a botnet");
    expect(result).toMatchObject({ sessionsEnded: 1, reason: "Logins from a botnet" });
    expect(result.tokensRevoked).toBeGreaterThanOrEqual(1);
    expect(await validateSession(token)).toBeNull();
    expect(await resolveAccessToken(access.token)).toBeNull();
    expect(await RefreshToken.countDocuments({ userId: user._id, revokedAt: null })).toBe(0);
    const stored = await User.findById(user._id).select("+passwordHash").lean();
    expect(stored).toMatchObject({ passwordHash: null, mustResetPassword: true, lockReason: "Logins from a botnet" });

    // Nothing gets in while locked, the old password least of all.
    await expect(loginUser({ email: user.email, password } as never, {})).rejects.toMatchObject({ status: 401 });
    expect(sent.some((m) => m.to === user.email && m.subject === "Your Noirly account is locked")).toBe(true);
    expect(await IdentityEvent.countDocuments({ action: "account.contained" })).toBe(2);
  });

  it("unlocks with a link to choose a new password, and the reset finishes it", async () => {
    const { user: admin } = await createTestUser({ email: "admin@example.com" });
    const { user } = await createTestUser({ email: "victim@example.com" });
    await containAccount(String(admin._id), { userId: String(user._id) }, "Phished credentials");
    await expect(unlockAccount(String(admin._id), { userId: String(user._id) })).resolves.toBeUndefined();
    const resetEmail = sent.filter((m) => m.to === user.email).at(-1)!;
    const token = new URL(resetEmail.text.match(/https?:\/\/\S+/)![0]).searchParams.get("token")!;
    await resetUserPassword(token, "A-brand-new-one-9!");
    const after = await User.findById(user._id).lean();
    expect(after).toMatchObject({ lockedAt: null, mustResetPassword: false });
    await expect(loginUser({ email: user.email, password: "A-brand-new-one-9!" } as never, {})).resolves.toBeTruthy();
  });

  it("asks for a reason and refuses odd targets", async () => {
    const { user: admin } = await createTestUser({ email: "admin@example.com" });
    await expect(containAccount(String(admin._id), { email: "nobody@example.com" }, "Because reasons")).rejects.toMatchObject({ status: 404 });
    await expect(containAccount(String(admin._id), { email: "admin@example.com" }, "Because reasons")).rejects.toMatchObject({ status: 400 });
    const { user } = await createTestUser({ email: "x@example.com" });
    await expect(containAccount(String(admin._id), { userId: String(user._id) }, "no")).rejects.toMatchObject({ status: 400 });
    await expect(unlockAccount(String(admin._id), { userId: String(user._id) })).rejects.toMatchObject({ code: "not_locked" });
  });
});
