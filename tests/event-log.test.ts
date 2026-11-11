import { createHash } from "node:crypto";
import mongoose from "mongoose";
import { describe, expect, it } from "vitest";
import { ChainChecker, GENESIS_HASH, hashInput, userStream, type ChainEvent, type EventFields } from "@/lib/audit/chain";
import { listEvents, recordEvent, verifyStream } from "@/lib/audit/event-log";
import { changeUserPassword, loginUser } from "@/lib/auth/auth-service";
import { deleteUserAccount } from "@/lib/account/delete-account";
import { requireSecondFactor } from "@/lib/security/mfa";
import { issueRefreshToken, rotateRefreshToken } from "@/lib/tokens/token-service";
import { IdentityEvent } from "@/models/IdentityEvent";
import { Passkey, SecurityChallenge } from "@/models/SecurityCredential";
import { createAuthedSession, createTestUser } from "./helpers";

const sha256 = (text: string) => createHash("sha256").update(text).digest("hex");
const meta = { ipAddress: "203.0.113.7", userAgent: "vitest" };

function chain(count: number): ChainEvent[] {
  const events: ChainEvent[] = [];
  let prevHash = GENESIS_HASH;
  for (let seq = 1; seq <= count; seq++) {
    const fields: EventFields = { stream: "admin", seq, at: `2026-11-02T00:00:0${seq}.000Z`, action: "client.updated", actorId: null, subjectId: null, clientId: "app", ipAddress: null, userAgent: null, data: { n: seq } };
    const hash = sha256(hashInput(prevHash, fields));
    events.push({ ...fields, prevHash, hash });
    prevHash = hash;
  }
  return events;
}

function check(events: ChainEvent[]) {
  const checker = new ChainChecker(sha256);
  for (const event of events) checker.add(event);
  return checker.result();
}

describe("hash chain", () => {
  it("accepts an untouched chain and finds edits, gaps and repeats", () => {
    const events = chain(4);
    expect(check(events)).toMatchObject({ ok: true, events: 4, lastHash: events[3]!.hash });
    expect(check(events.map((e) => (e.seq === 2 ? { ...e, data: { n: 99 } } : e)))).toEqual({ ok: false, events: 1, brokenAt: 2, reason: "Event 2 was changed after it was written" });
    expect(check(events.filter((e) => e.seq !== 3))).toMatchObject({ ok: false, brokenAt: 3, reason: "Event 3 is missing" });
    expect(check([events[0]!, events[0]!])).toMatchObject({ ok: false, reason: "Event 1 appears twice" });
  });
});

describe("identity event log", () => {
  it("chains each stream on its own, even with writers racing", async () => {
    const { user } = await createTestUser();
    const id = String(user._id);
    await Promise.all(Array.from({ length: 8 }, (_, i) => recordEvent({ action: "account.profile_updated", subjectId: id, data: { i } })));
    await recordEvent({ action: "client.deleted", actorId: id, clientId: "gone" });
    const mine = await IdentityEvent.find({ stream: userStream(id) }).sort({ seq: 1 }).lean();
    expect(mine.map((e) => e.seq)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(await verifyStream(userStream(id))).toMatchObject({ ok: true, events: 8 });
    expect(await verifyStream("admin")).toMatchObject({ ok: true, events: 1 });
  });

  it("refuses changes through the app and shows changes made around it", async () => {
    const { user } = await createTestUser();
    const stream = userStream(String(user._id));
    await recordEvent({ action: "auth.signed_in", subjectId: user._id, request: meta, data: { methods: ["password"] } });
    await recordEvent({ action: "auth.signed_out", subjectId: user._id });
    await expect(IdentityEvent.updateOne({ stream }, { $set: { ipAddress: "1.1.1.1" } })).rejects.toThrow("can't be changed");
    await expect(IdentityEvent.deleteMany({ stream })).rejects.toThrow("can't be changed");
    // Straight in the database, past the app.
    await mongoose.connection.db!.collection("identity_events").updateOne({ stream, seq: 1 }, { $set: { ipAddress: "1.1.1.1" } });
    expect(await verifyStream(stream)).toMatchObject({ ok: false, brokenAt: 1, reason: "Event 1 was changed after it was written" });
  });

  it("records password sign-ins and failures, but not guesses at unknown addresses", async () => {
    const { user, password } = await createTestUser();
    await expect(loginUser({ email: user.email, password: "WrongPass1!" }, meta)).rejects.toMatchObject({ code: "invalid_credentials" });
    await expect(loginUser({ email: "nobody@example.com", password: "WrongPass1!" }, meta)).rejects.toMatchObject({ code: "invalid_credentials" });
    await loginUser({ email: user.email, password }, meta);
    const { events } = await listEvents({ stream: userStream(String(user._id)) });
    expect(events.map((e) => e.action)).toEqual(["auth.signed_in", "auth.sign_in_failed"]);
    expect(events[0]).toMatchObject({ ipAddress: "203.0.113.7", userAgent: "vitest", data: { methods: ["password"] }, actorId: String(user._id) });
    expect(events[1]).toMatchObject({ actorId: null, data: { reason: "wrong_password" } });
    expect(await IdentityEvent.countDocuments()).toBe(2);
  });

  it("remembers the first step on a sign-in that needs a second factor", async () => {
    const { user } = await createTestUser();
    await Passkey.create({ userId: user._id, credentialId: "cred", publicKey: "key", counter: 0 });
    await expect(requireSecondFactor(String(user._id), undefined, "google")).rejects.toMatchObject({ code: "mfa_required" });
    expect((await SecurityChallenge.findOne({ userId: user._id }).lean())?.method).toBe("google");
  });

  it("records a password change without the password", async () => {
    const { user, password } = await createTestUser();
    const { token } = await createAuthedSession(String(user._id));
    await changeUserPassword(token, { currentPassword: password, newPassword: "AnotherPass2@" }, meta);
    const [event] = (await listEvents({ action: "password." })).events;
    expect(event).toMatchObject({ action: "password.changed", subjectId: String(user._id), data: { otherSessionsSignedOut: true } });
    expect(JSON.stringify(event)).not.toContain("AnotherPass2@");
  });

  it("records refresh token reuse against the account", async () => {
    const { user } = await createTestUser();
    const { session } = await createAuthedSession(String(user._id));
    const { token } = await issueRefreshToken({ clientId: "app", userId: user._id, sessionId: session._id, scope: "openid" });
    expect((await rotateRefreshToken(token, "app")).error).toBeNull();
    expect((await rotateRefreshToken(token, "app")).error).toBe("reuse_detected");
    const [event] = (await listEvents({ action: "oauth.refresh_reuse_detected" })).events;
    expect(event).toMatchObject({ subjectId: String(user._id), actorId: null, clientId: "app", data: { familyRevoked: true } });
  });

  it("takes an account's history with it when it's deleted, keeping only that it went", async () => {
    const { user, password } = await createTestUser();
    await loginUser({ email: user.email, password }, meta);
    await deleteUserAccount(user._id);
    expect(await IdentityEvent.countDocuments({ stream: userStream(String(user._id)) })).toBe(0);
    const [gone] = (await listEvents({ stream: "system" })).events;
    expect(gone).toMatchObject({ action: "account.deleted", subjectId: String(user._id), ipAddress: null, userAgent: null });
  });

  it("pages newest first and rejects unknown filters", async () => {
    for (let i = 0; i < 5; i++) await recordEvent({ action: "client.updated", actorId: null, clientId: `c${i}` });
    const first = await listEvents({ stream: "admin", limit: 2 });
    expect(first.events.map((e) => e.clientId)).toEqual(["c4", "c3"]);
    const second = await listEvents({ stream: "admin", limit: 2, before: first.nextBefore! });
    expect(second.events.map((e) => e.clientId)).toEqual(["c2", "c1"]);
    await expect(listEvents({ stream: "user:nope" })).rejects.toMatchObject({ code: "invalid_request" });
    await expect(listEvents({ action: "made.up" })).rejects.toMatchObject({ code: "invalid_request" });
  });
});
