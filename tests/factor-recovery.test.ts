import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { listEvents } from "@/lib/audit/event-log";
import { resetEmailProvider, setEmailProvider, type EmailMessage } from "@/lib/email/email-service";
import { requireSecondFactor } from "@/lib/security/mfa";
import { cancelFactorRecovery, finishFactorRecovery, recoveryStatus, startFactorRecovery } from "@/lib/security/recovery";
import { createSession, validateSession } from "@/lib/sessions/session-service";
import { FactorRecovery } from "@/models/FactorRecovery";
import { Mfa, Passkey } from "@/models/SecurityCredential";
import { User } from "@/models/User";
import { UserEmail } from "@/models/UserEmail";
import { createTestUser } from "./helpers";

let sent: EmailMessage[] = [];
beforeEach(() => {
  sent = [];
  setEmailProvider({ send: async (message) => { sent.push(message); } });
});
afterEach(() => resetEmailProvider());

/** A user with a second step, part-way through signing in: the verification screen's challenge. */
async function atVerification(email = "lost@example.com") {
  const { user } = await createTestUser({ email });
  await Mfa.create({ userId: user._id, enabled: true, secret: "x" });
  await Passkey.create({ userId: user._id, credentialId: `key-${email}`, publicKey: "k", counter: 0 });
  const challenge = await requireSecondFactor(String(user._id), undefined, "password").catch((error: { details: { challenge: string } }) => error.details.challenge);
  return { user, challenge: challenge as string };
}

const cancelTokenIn = (message: EmailMessage) => new URL(message.text.match(/https?:\/\/\S+/)![0]).searchParams.get("token")!;

describe("lost second step", () => {
  it("waits, tells every address, then removes the second steps and signs in", async () => {
    const { user, challenge } = await atVerification();
    await UserEmail.create({ userId: user._id, email: "backup@example.com", verifiedAt: new Date() });
    const other = await createSession({ userId: user._id, methods: ["password", "totp"] });

    expect(await recoveryStatus(challenge)).toEqual({ state: "none", hasRecoveryMethod: false });
    const waiting = await startFactorRecovery(challenge, { ipAddress: "203.0.113.7" });
    expect(waiting.state).toBe("waiting");
    expect(sent.map((m) => m.to).sort()).toEqual(["backup@example.com", "lost@example.com"]);
    // Asking again doesn't start another wait or send more.
    await startFactorRecovery(challenge);
    expect(sent).toHaveLength(2);
    await expect(finishFactorRecovery(challenge)).rejects.toMatchObject({ code: "recovery_waiting" });

    await FactorRecovery.updateMany({}, { $set: { availableAt: new Date(Date.now() - 1000) } });
    expect((await recoveryStatus(challenge)).state).toBe("ready");
    const { sessionToken } = await finishFactorRecovery(challenge, { ipAddress: "203.0.113.7" });
    expect(await validateSession(sessionToken)).toMatchObject({ session: { methods: ["password"] } });
    expect(await validateSession(other.token)).toBeNull();
    expect(await Mfa.countDocuments({ userId: user._id })).toBe(0);
    expect(await Passkey.countDocuments({ userId: user._id })).toBe(0);
    expect(sent.at(-1)).toMatchObject({ to: "lost@example.com", subject: "Your Noirly second sign-in steps were removed" });
    const actions = (await listEvents({ action: "recovery." })).events.map((e) => e.action);
    expect(actions).toEqual(["recovery.completed", "recovery.started"]);
  });

  it("can be cancelled from the emailed link, and then can't be finished", async () => {
    const { challenge } = await atVerification();
    await startFactorRecovery(challenge);
    await cancelFactorRecovery(cancelTokenIn(sent[0]!));
    await FactorRecovery.updateMany({}, { $set: { availableAt: new Date(Date.now() - 1000) } });
    expect(await recoveryStatus(challenge)).toEqual({ state: "none", hasRecoveryMethod: false });
    await expect(finishFactorRecovery(challenge)).rejects.toMatchObject({ code: "no_recovery" });
    await expect(cancelFactorRecovery(cancelTokenIn(sent[0]!))).rejects.toMatchObject({ code: "recovery_done" });
  });

  it("needs the first step passed: no challenge, no request", async () => {
    await expect(startFactorRecovery(null)).rejects.toMatchObject({ code: "invalid_challenge" });
    await expect(startFactorRecovery("x".repeat(43))).rejects.toMatchObject({ code: "invalid_challenge" });
  });

  it("drops the account's own requirement, so it can sign in again", async () => {
    const { user, challenge } = await atVerification();
    await User.updateOne({ _id: user._id }, { $set: { mfaRequired: true } });
    await startFactorRecovery(challenge);
    await FactorRecovery.updateMany({}, { $set: { availableAt: new Date(Date.now() - 1000) } });
    await finishFactorRecovery(challenge);
    expect((await User.findById(user._id).lean())!.mfaRequired).toBe(false);
  });
});
