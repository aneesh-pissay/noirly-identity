import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { confirmRecoveryEmail, recoveryMethods, removeRecoveryEmail, startRecoveryEmail } from "@/lib/account/recovery-methods";
import { resetEmailProvider, setEmailProvider, type EmailMessage } from "@/lib/email/email-service";
import { newChallenge } from "@/lib/security/mfa";
import { decideRecoveryReview, finishFactorRecovery, listRecoveryReviews, recoveryStatus, RECOVERY_WAIT_HOURS, RECOVERY_WAIT_HOURS_UNVERIFIED, sendRecoveryProof, startFactorRecovery } from "@/lib/security/recovery";
import { noteSignIn } from "@/lib/security/risk";
import { FactorRecovery } from "@/models/FactorRecovery";
import { UserEmail } from "@/models/UserEmail";
import { createTestUser } from "./helpers";

let sent: EmailMessage[] = [];
beforeEach(() => { sent = []; setEmailProvider({ send: async (m) => { sent.push(m); } }); });
afterEach(() => resetEmailProvider());

const codeIn = (m: EmailMessage) => /(\d{6})/.exec(m.subject)![1]!;
const HOUR = 3_600_000;

async function withRecoveryAddress() {
  const { user } = await createTestUser({ email: "owner@example.com" });
  const id = String(user._id);
  await startRecoveryEmail(id, "Backup@Elsewhere.example");
  await confirmRecoveryEmail(id, codeIn(sent.at(-1)!));
  return { user, id };
}

describe("recovery methods", () => {
  it("add a recovery address after proving it, never one used to sign in, and remove it", async () => {
    const { user } = await createTestUser({ email: "owner@example.com" });
    const id = String(user._id);
    await expect(startRecoveryEmail(id, "owner@example.com")).rejects.toMatchObject({ code: "same_address" });
    await UserEmail.create({ userId: user._id, email: "second@example.com", verifiedAt: new Date() });
    await expect(startRecoveryEmail(id, "second@example.com")).rejects.toMatchObject({ code: "same_address" });

    await startRecoveryEmail(id, "backup@elsewhere.example");
    expect(await recoveryMethods(id)).toMatchObject({ email: null, pendingEmail: "backup@elsewhere.example" });
    await expect(confirmRecoveryEmail(id, "000000" === codeIn(sent.at(-1)!) ? "111111" : "000000")).rejects.toMatchObject({ code: "invalid_code" });
    await confirmRecoveryEmail(id, codeIn(sent.at(-1)!));
    expect(await recoveryMethods(id)).toMatchObject({ email: "backup@elsewhere.example", pendingEmail: null });
    // The owner is told (a security alert).
    expect(sent.some((m) => m.to === "owner@example.com" && m.subject === "Recovery address added")).toBe(true);
    await removeRecoveryEmail(id);
    expect((await recoveryMethods(id)).email).toBeNull();
  });
});

describe("recovery through verified methods", () => {
  it("needs a code sent to a recovery method, then waits the shorter time, telling every channel", async () => {
    const { id } = await withRecoveryAddress();
    const challenge = await newChallenge({ userId: id, purpose: "login-mfa", method: "password" });
    expect(await recoveryStatus(challenge)).toEqual({ state: "none", hasRecoveryMethod: true });
    await expect(startFactorRecovery(challenge, {})).rejects.toMatchObject({ code: "recovery_code_required" });

    await sendRecoveryProof(challenge);
    const proof = sent.at(-1)!;
    expect(proof.to).toBe("backup@elsewhere.example");
    sent = [];
    const status = await startFactorRecovery(challenge, {}, codeIn(proof));
    expect(status.state).toBe("waiting");
    const wait = new Date((status as { availableAt: string }).availableAt).getTime() - Date.now();
    expect(Math.round(wait / HOUR)).toBe(RECOVERY_WAIT_HOURS);
    // Every address hears, the recovery address included.
    expect(sent.map((m) => m.to).sort()).toEqual(["backup@elsewhere.example", "owner@example.com"]);
  });

  it("waits longer for an account without a recovery method", async () => {
    const { user } = await createTestUser();
    const challenge = await newChallenge({ userId: String(user._id), purpose: "login-mfa", method: "password" });
    const status = await startFactorRecovery(challenge, {});
    expect(Math.round((new Date((status as { availableAt: string }).availableAt).getTime() - Date.now()) / HOUR)).toBe(RECOVERY_WAIT_HOURS_UNVERIFIED);
    await expect(sendRecoveryProof(challenge)).rejects.toMatchObject({ code: "no_recovery_method" });
  });
});

describe("high-risk recovery review", () => {
  it("holds a recovery started from somewhere risky until an admin approves it", async () => {
    const { user } = await createTestUser({ email: "owner@example.com" });
    const { user: admin } = await createTestUser({ email: "admin@example.com" });
    const id = String(user._id);
    await noteSignIn(id, { deviceId: "home-device-000000001", place: "Pune, IN", at: new Date(Date.now() - 72 * HOUR) });
    const challenge = await newChallenge({ userId: id, purpose: "login-mfa", method: "password" });
    const status = await startFactorRecovery(challenge, { deviceId: "strange-device-0000001", place: "Lagos, NG" });
    expect(status.state).toBe("review");
    const [queued] = await listRecoveryReviews();
    expect(queued).toMatchObject({ email: "owner@example.com", signals: ["new_device", "new_country"] });

    await FactorRecovery.updateMany({}, { $set: { availableAt: new Date(Date.now() - 1000) } });
    await expect(finishFactorRecovery(challenge)).rejects.toMatchObject({ code: "recovery_in_review" });
    await decideRecoveryReview(String(admin._id), queued!.id, true);
    expect(sent.at(-1)).toMatchObject({ to: "owner@example.com", subject: "Your account recovery can go on" });
    await expect(finishFactorRecovery(challenge)).resolves.toMatchObject({ sessionToken: expect.any(String) });
    expect(await listRecoveryReviews()).toEqual([]);
  });

  it("can decline one, which ends it", async () => {
    const { user } = await createTestUser({ email: "owner@example.com" });
    const { user: admin } = await createTestUser({ email: "admin@example.com" });
    const id = String(user._id);
    await noteSignIn(id, { deviceId: "home-device-000000001", place: "Pune, IN", at: new Date(Date.now() - 72 * HOUR) });
    const challenge = await newChallenge({ userId: id, purpose: "login-mfa", method: "password" });
    await startFactorRecovery(challenge, { deviceId: "strange-device-0000001", place: "Lagos, NG" });
    const [queued] = await listRecoveryReviews();
    await decideRecoveryReview(String(admin._id), queued!.id, false);
    expect((await recoveryStatus(challenge)).state).toBe("none");
    await expect(decideRecoveryReview(String(admin._id), queued!.id, true)).rejects.toMatchObject({ status: 404 });
  });
});
