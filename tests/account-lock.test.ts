import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loginUser } from "@/lib/auth/auth-service";
import { recordEvent } from "@/lib/audit/event-log";
import { resetEmailProvider, setEmailProvider, type EmailMessage } from "@/lib/email/email-service";
import { adminLock, cancelUnfreeze, confirmUnfreeze, freezeAccount, freezeByLink, requestUnfreeze } from "@/lib/security/account-lock";
import { unlockAccount } from "@/lib/security/containment";
import { createSession, validateSession } from "@/lib/sessions/session-service";
import { User } from "@/models/User";
import { createTestUser } from "./helpers";

let sent: EmailMessage[] = [];
beforeEach(() => { sent = []; setEmailProvider({ send: async (m) => { sent.push(m); } }); });
afterEach(() => resetEmailProvider());

const linkIn = (m: EmailMessage, path: string) => {
  const url = m.text.match(new RegExp(`https?://\\S+${path}\\?token=\\S+`))![0];
  return new URL(url).searchParams.get("token")!;
};

describe("freezing your own account", () => {
  it("stops every sign-in at once, and unfreezes only a day after confirming by email", async () => {
    const { user, password } = await createTestUser({ email: "owner@example.com" });
    const id = String(user._id);
    const { token } = await createSession({ userId: id });
    await freezeAccount(id);
    expect(await validateSession(token)).toBeNull();
    await expect(loginUser({ email: user.email, password } as never, {})).rejects.toMatchObject({ status: 401 });

    sent = [];
    await requestUnfreeze("owner@example.com");
    const confirm = linkIn(sent.at(-1)!, "/unfreeze");
    const { unlockAt } = await confirmUnfreeze(confirm);
    expect(new Date(unlockAt).getTime() - Date.now()).toBeGreaterThan(23 * 3600_000);
    // Still frozen during the wait.
    await expect(loginUser({ email: user.email, password } as never, {})).rejects.toMatchObject({ status: 401 });
    // After it, in.
    await User.updateOne({ _id: id }, { $set: { unlockAt: new Date(Date.now() - 1000) } });
    await expect(loginUser({ email: user.email, password } as never, {})).resolves.toBeTruthy();
  });

  it("can be kept frozen from the link in the 'unfreezes tomorrow' email", async () => {
    const { user, password } = await createTestUser({ email: "owner@example.com" });
    const id = String(user._id);
    await freezeAccount(id);
    await requestUnfreeze("owner@example.com");
    await confirmUnfreeze(linkIn(sent.at(-1)!, "/unfreeze"));
    const keepFrozen = linkIn(sent.at(-1)!, "/unfreeze");
    await cancelUnfreeze(keepFrozen);
    await User.updateOne({ _id: id }, { $set: { lockedAt: new Date() } });
    expect((await User.findById(id).lean())?.unlockAt).toBeNull();
    await expect(loginUser({ email: user.email, password } as never, {})).rejects.toMatchObject({ status: 401 });
  });

  it("works from the link in any security alert, without signing in", async () => {
    const { user } = await createTestUser({ email: "owner@example.com" });
    await recordEvent({ action: "password.changed", subjectId: user._id });
    const alert = sent.find((m) => m.subject === "Password changed")!;
    await freezeByLink(linkIn(alert, "/freeze"));
    expect((await User.findById(user._id).lean())?.lockKind).toBe("self");
    await expect(freezeByLink(linkIn(alert, "/freeze"))).rejects.toMatchObject({ code: "invalid_token" });
  });

  it("says nothing about accounts that don't exist or aren't frozen when asked to unfreeze", async () => {
    await createTestUser({ email: "fine@example.com" });
    await requestUnfreeze("fine@example.com");
    await requestUnfreeze("nobody@example.com");
    expect(sent).toEqual([]);
  });
});

describe("admin locks", () => {
  it("lock with a reason, can't be unfrozen by the owner, and are unlocked by an admin", async () => {
    const { user: admin } = await createTestUser({ email: "admin@example.com" });
    const { user, password } = await createTestUser({ email: "owner@example.com" });
    await adminLock(String(admin._id), String(user._id), "Chargeback fraud investigation");
    expect(await User.findById(user._id).lean()).toMatchObject({ lockKind: "admin", lockReason: "Chargeback fraud investigation" });
    await requestUnfreeze("owner@example.com");
    expect(sent.filter((m) => m.subject.startsWith("Unfreeze"))).toEqual([]);
    await unlockAccount(String(admin._id), { userId: String(user._id) });
    await expect(loginUser({ email: user.email, password } as never, {})).resolves.toBeTruthy();
  });
});
