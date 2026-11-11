import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { changeUserPassword, flagIfBreached, registerUser, resetUserPassword } from "@/lib/auth/auth-service";
import { setPassword } from "@/lib/account/identities";
import { resetEmailProvider, setEmailProvider, type EmailMessage } from "@/lib/email/email-service";
import { breachCount, setBreachRangeFetcher } from "@/lib/security/breached-passwords";
import { createSession } from "@/lib/sessions/session-service";
import { IdentityEvent } from "@/models/IdentityEvent";
import { User } from "@/models/User";
import { createTestUser } from "./helpers";

const BREACHED = "Password123!";
const asked: string[] = [];
let sent: EmailMessage[] = [];

beforeEach(() => {
  asked.length = 0;
  sent = [];
  setEmailProvider({ send: async (m) => { sent.push(m); } });
  const hash = createHash("sha1").update(BREACHED).digest("hex").toUpperCase();
  setBreachRangeFetcher(async (prefix) => {
    asked.push(prefix);
    // A padded answer: other suffixes, some with zero counts, and the breached one when it's this range.
    const lines = ["0000000000000000000000000000000000A:0", "1234567890ABCDEF1234567890ABCDEF123:5"];
    if (prefix === hash.slice(0, 5)) lines.push(`${hash.slice(5)}:4210`);
    return lines.join("\r\n");
  });
});
afterEach(() => {
  setBreachRangeFetcher(null);
  resetEmailProvider();
});

describe("compromised password checks", () => {
  it("send only a five-character prefix, and find a breached password", async () => {
    expect(await breachCount(BREACHED)).toBe(4210);
    expect(await breachCount("a-much-better-one-9!Q")).toBe(0);
    expect(asked.every((p) => /^[0-9A-F]{5}$/.test(p))).toBe(true);
  });

  it("pass when the lookup fails, rather than blocking sign-in", async () => {
    setBreachRangeFetcher(async () => { throw new Error("offline"); });
    expect(await breachCount(BREACHED)).toBe(0);
  });

  it("refuse a breached password at sign-up, change, reset and when adding one", async () => {
    await expect(registerUser({ email: "new@example.com", password: BREACHED, firstName: "N", lastName: "U" } as never, {})).rejects.toMatchObject({ code: "breached_password" });

    const { user, password } = await createTestUser();
    const { token } = await createSession({ userId: user._id });
    await expect(changeUserPassword(token, { currentPassword: password, newPassword: BREACHED } as never)).rejects.toMatchObject({ code: "breached_password" });

    await User.updateOne({ _id: user._id }, { $set: { passwordHash: null } });
    await expect(setPassword(String(user._id), BREACHED)).rejects.toMatchObject({ code: "breached_password" });
    await expect(resetUserPassword("not-a-token", BREACHED)).rejects.toMatchObject({ status: 400 });
  });

  it("flag the account and email its owner when a sign-in uses one, once", async () => {
    const { user } = await createTestUser();
    await flagIfBreached(String(user._id), BREACHED);
    await flagIfBreached(String(user._id), BREACHED);
    expect((await User.findById(user._id).lean())?.passwordBreachedAt).toBeTruthy();
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({ to: user.email, subject: "Change your Noirly password" });
    expect(await IdentityEvent.countDocuments({ action: "password.breach_detected" })).toBe(1);

    // Changing it clears the flag.
    const { token } = await createSession({ userId: user._id });
    await changeUserPassword(token, { currentPassword: "StrongPass1!", newPassword: "A-new-safe-one-9!" } as never);
    expect((await User.findById(user._id).lean())?.passwordBreachedAt).toBeNull();
  });
});
