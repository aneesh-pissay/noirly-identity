import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { addEmailAddress, listEmailAddresses, makePrimaryEmail, MAX_ADDITIONAL, removeEmailAddress, resendAddressVerification, undoPrimaryChange } from "@/lib/account/emails";
import { EmailChangeUndo } from "@/models/EmailChangeUndo";
import { Session } from "@/models/Session";
import { deleteUserAccount } from "@/lib/account/delete-account";
import { listEvents } from "@/lib/audit/event-log";
import { userStream } from "@/lib/audit/chain";
import { registerUser } from "@/lib/auth/auth-service";
import { verifyEmailToken } from "@/lib/auth/email-tokens";
import { resetEmailProvider, setEmailProvider, type EmailMessage } from "@/lib/email/email-service";
import { User } from "@/models/User";
import { UserEmail } from "@/models/UserEmail";
import { createAuthedSession, createTestUser } from "./helpers";

let sent: EmailMessage[] = [];

beforeEach(() => {
  sent = [];
  setEmailProvider({ send: async (message) => { sent.push(message); } });
});

afterEach(() => resetEmailProvider());

/** The token in the last link sent to an address. */
function linkTo(email: string) {
  const message = sent.filter((m) => m.to === email).at(-1);
  const url = message?.text.match(/https?:\/\/\S+/)?.[0];
  return url ? new URL(url).searchParams.get("token")! : null;
}

async function addAndConfirm(userId: string, email: string) {
  await addEmailAddress(userId, email);
  expect(await verifyEmailToken(linkTo(email)!)).toEqual({ status: "verified" });
}

describe("additional email addresses", () => {
  it("adds an address, confirms it by a link sent to it, and can remove it", async () => {
    const { user } = await createTestUser();
    const id = String(user._id);
    const added = await addEmailAddress(id, "  Work@Example.com ");
    expect(added.additional).toEqual([expect.objectContaining({ email: "work@example.com", verified: false })]);
    const message = sent.find((m) => m.to === "work@example.com")!;
    expect(message.text).toContain("u***@example.com");
    expect(await verifyEmailToken(linkTo("work@example.com")!)).toEqual({ status: "verified" });
    expect(await verifyEmailToken(linkTo("work@example.com")!)).toEqual({ status: "already_verified" });
    expect((await listEmailAddresses(id)).additional[0]!.verified).toBe(true);

    const removed = await removeEmailAddress(id, added.additional[0]!.id);
    expect(removed.additional).toEqual([]);
    const actions = (await listEvents({ stream: userStream(id) })).events.map((e) => e.action);
    expect(actions).toEqual(["email.removed", "email.verified", "email.added"]);
  });

  it("refuses the primary address, duplicates, addresses another account holds, and more than the limit", async () => {
    const { user } = await createTestUser();
    const other = await createTestUser({ email: "taken@example.com" });
    const id = String(user._id);
    await expect(addEmailAddress(id, user.email)).rejects.toMatchObject({ code: "already_primary" });
    await expect(addEmailAddress(id, "taken@example.com")).rejects.toMatchObject({ code: "address_unavailable" });
    await addAndConfirm(String(other.user._id), "theirs@example.com");
    await expect(addEmailAddress(id, "theirs@example.com")).rejects.toMatchObject({ code: "address_unavailable" });
    await addEmailAddress(id, "a@example.com");
    await expect(addEmailAddress(id, "a@example.com")).rejects.toMatchObject({ code: "already_added" });
    for (let i = 1; i < MAX_ADDITIONAL; i++) await addEmailAddress(id, `extra${i}@example.com`);
    await expect(addEmailAddress(id, "one-more@example.com")).rejects.toMatchObject({ code: "address_limit" });
  });

  it("lets two people claim an address but only the first to confirm it keep it", async () => {
    const first = await createTestUser({ email: "first@example.com" });
    const second = await createTestUser({ email: "second@example.com" });
    await addEmailAddress(String(first.user._id), "shared@example.com");
    const firstToken = linkTo("shared@example.com")!;
    await addEmailAddress(String(second.user._id), "shared@example.com");
    const secondToken = linkTo("shared@example.com")!;
    expect(await verifyEmailToken(secondToken)).toEqual({ status: "verified" });
    // The first claim was dropped when the second was confirmed.
    expect(await verifyEmailToken(firstToken)).toEqual({ status: "invalid" });
    expect(await UserEmail.countDocuments({ email: "shared@example.com" })).toBe(1);
  });

  it("limits how often a link is sent again", async () => {
    const { user } = await createTestUser();
    const { additional } = await addEmailAddress(String(user._id), "slow@example.com");
    for (let i = 0; i < 3; i++) await resendAddressVerification(String(user._id), additional[0]!.id);
    await expect(resendAddressVerification(String(user._id), additional[0]!.id)).rejects.toMatchObject({ code: "resend_cooldown" });
  });

  it("makes a confirmed address primary, keeps the old one, and tells the old one", async () => {
    const { user } = await createTestUser({ email: "old@example.com" });
    const id = String(user._id);
    await addEmailAddress(id, "pending@example.com");
    const pending = (await listEmailAddresses(id)).additional[0]!;
    await expect(makePrimaryEmail(id, pending.id)).rejects.toMatchObject({ code: "not_verified" });
    await addAndConfirm(id, "new@example.com");
    const confirmed = (await listEmailAddresses(id)).additional.find((a) => a.email === "new@example.com")!;

    const after = await makePrimaryEmail(id, confirmed.id, { ipAddress: "203.0.113.7", userAgent: "vitest" });
    expect(after.primary).toBe("new@example.com");
    expect(after.additional.map((a) => [a.email, a.verified])).toEqual([["pending@example.com", false], ["old@example.com", true]]);
    expect((await User.findById(id).lean())!.email).toBe("new@example.com");
    expect(sent.at(-1)).toMatchObject({ to: "old@example.com", subject: "Your Noirly primary email address changed" });
    const [event] = (await listEvents({ action: "email.primary_changed" })).events;
    expect(event).toMatchObject({ data: { from: "old@example.com", to: "new@example.com" }, ipAddress: "203.0.113.7" });
  });

  it("keeps confirmed addresses from being registered by someone else", async () => {
    const { user } = await createTestUser();
    await addAndConfirm(String(user._id), "alias@example.com");
    await expect(registerUser({ email: "alias@example.com", password: "StrongPass1!", firstName: "A", lastName: "B" }, {})).rejects.toMatchObject({ code: "registration_failed" });
    expect(await User.countDocuments()).toBe(1);
  });

  it("lets the old address undo a change, locking out whoever made it", async () => {
    const { user } = await createTestUser({ email: "owner@example.com" });
    const id = String(user._id);
    await addAndConfirm(id, "intruder@example.com");
    const intruder = (await listEmailAddresses(id)).additional[0]!;
    const { session } = await createAuthedSession(id);
    await makePrimaryEmail(id, intruder.id);
    const undoToken = linkTo("owner@example.com")!;
    expect(sent.at(-1)!.text).toContain("/undo-email-change?token=");

    const result = await undoPrimaryChange(undoToken, { ipAddress: "198.51.100.4", userAgent: "vitest" });
    expect(result).toEqual({ email: "o***@example.com", passwordResetSent: true });
    expect((await User.findById(id).lean())!.email).toBe("owner@example.com");
    expect(await UserEmail.countDocuments({ userId: user._id })).toBe(0);
    expect((await Session.findById(session._id).lean())!.revokedAt).not.toBeNull();
    expect(sent.at(-1)).toMatchObject({ to: "owner@example.com", subject: "Reset your Noirly password" });
    const [event] = (await listEvents({ action: "email.change_undone" })).events;
    expect(event).toMatchObject({ actorId: null, data: { restored: "owner@example.com", removed: ["intruder@example.com"], signedOutEverywhere: true } });
    await expect(undoPrimaryChange(undoToken)).rejects.toMatchObject({ code: "token_used" });
  });

  it("refuses an expired undo link, and one for an address someone else now holds", async () => {
    const { user } = await createTestUser({ email: "mine@example.com" });
    const id = String(user._id);
    await addAndConfirm(id, "next@example.com");
    await makePrimaryEmail(id, (await listEmailAddresses(id)).additional[0]!.id);
    const token = linkTo("mine@example.com")!;
    // The old address dropped from the account, then taken by another.
    await removeEmailAddress(id, (await listEmailAddresses(id)).additional.find((a) => a.email === "mine@example.com")!.id);
    await createTestUser({ email: "mine@example.com" });
    await expect(undoPrimaryChange(token)).rejects.toMatchObject({ code: "address_unavailable" });
    await EmailChangeUndo.updateMany({}, { $set: { expiresAt: new Date(Date.now() - 1000) } });
    await expect(undoPrimaryChange(token)).rejects.toMatchObject({ code: "token_expired" });
    await expect(undoPrimaryChange("x".repeat(40))).rejects.toMatchObject({ code: "invalid_token" });
  });

  it("goes with the account when it's deleted", async () => {
    const { user } = await createTestUser();
    await addAndConfirm(String(user._id), "gone@example.com");
    await deleteUserAccount(user._id);
    expect(await UserEmail.countDocuments()).toBe(0);
  });
});
