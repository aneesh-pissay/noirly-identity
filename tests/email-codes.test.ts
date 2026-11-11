import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { listEvents } from "@/lib/audit/event-log";
import { registerUser } from "@/lib/auth/auth-service";
import { verifyEmailCode, verifyEmailToken } from "@/lib/auth/email-tokens";
import { requestMagicLink, verifyMagicCode, verifyMagicLink } from "@/lib/auth/magic-link";
import { resetEmailProvider, setEmailProvider, type EmailMessage } from "@/lib/email/email-service";
import { emailCodeHash, emailCodeMatches, newEmailCode, spacedCode } from "@/lib/security/email-code";
import { User } from "@/models/User";
import { createTestUser } from "./helpers";

let sent: EmailMessage[] = [];

beforeEach(() => {
  sent = [];
  setEmailProvider({ send: async (message) => { sent.push(message); } });
});

afterEach(() => resetEmailProvider());

/** The six-digit code in an email ("123 456" in the text). */
const codeIn = (message: EmailMessage) => message.text.match(/(\d{3}) (\d{3})/)!.slice(1).join("");
const tokenIn = (message: EmailMessage) => new URL(message.text.match(/https?:\/\/\S+/)![0]).searchParams.get("token")!;

describe("email codes", () => {
  it("are six digits, only good for their own record", () => {
    const code = newEmailCode();
    expect(code).toMatch(/^\d{6}$/);
    expect(spacedCode("012345")).toBe("012 345");
    const stored = emailCodeHash("record-a", code);
    expect(emailCodeMatches("record-a", code, stored)).toBe(true);
    expect(emailCodeMatches("record-b", code, stored)).toBe(false);
    expect(emailCodeMatches("record-a", "abcdef", stored)).toBe(false);
  });
});

describe("sign-in codes", () => {
  it("sign in with the code from the sign-in email, in the browser that asked", async () => {
    const { user } = await createTestUser();
    const { browserSecret } = await requestMagicLink(user.email, null);
    expect(sent[0]!.subject).toMatch(/^Your Noirly sign-in code: \d{3} \d{3}$/);
    const code = codeIn(sent[0]!);
    await expect(verifyMagicCode(user.email, code, null)).rejects.toMatchObject({ code: "invalid_code" });
    await expect(verifyMagicCode(user.email, code, "x".repeat(43))).rejects.toMatchObject({ code: "invalid_code" });
    const result = await verifyMagicCode(user.email, `${code.slice(0, 3)} ${code.slice(3)}`, browserSecret);
    expect(result.returnTo).toBe("/account");
    // Code or link, it's one sign-in: the link is used up too.
    await expect(verifyMagicLink(tokenIn(sent[0]!), browserSecret)).rejects.toMatchObject({ code: "token_used" });
    const [event] = (await listEvents({ action: "auth.signed_in" })).events;
    expect(event!.data).toEqual({ methods: ["email_code"] });
  });

  it("stop working after five wrong tries, and every failure reads the same", async () => {
    const { user } = await createTestUser();
    const { browserSecret } = await requestMagicLink(user.email, null);
    const code = codeIn(sent[0]!);
    const wrong = code === "000000" ? "111111" : "000000";
    const errors = new Set<string>();
    for (let i = 0; i < 5; i++) {
      await verifyMagicCode(user.email, wrong, browserSecret).catch((error: Error) => errors.add(error.message));
    }
    await verifyMagicCode("nobody@example.com", code, browserSecret).catch((error: Error) => errors.add(error.message));
    expect(errors.size).toBe(1);
    await expect(verifyMagicCode(user.email, code, browserSecret)).rejects.toMatchObject({ code: "invalid_code" });
  });
});

describe("verification codes", () => {
  it("confirm a new account's address with the code from its verification email", async () => {
    await registerUser({ email: "new@example.com", password: "StrongPass1!", firstName: "New", lastName: "Person" }, {});
    const code = codeIn(sent[0]!);
    expect(await verifyEmailCode("new@example.com", "000001" === code ? "000002" : "000001")).toEqual({ status: "invalid" });
    expect(await verifyEmailCode("new@example.com", code)).toEqual({ status: "verified" });
    expect(await User.findOne({ email: "new@example.com" }).lean()).toMatchObject({ emailVerified: true, status: "active" });
    expect(await verifyEmailCode("new@example.com", code)).toEqual({ status: "already_verified" });
    // The link from the same email is spent with it.
    expect(await verifyEmailToken(tokenIn(sent[0]!))).toEqual({ status: "already_verified" });
  });

  it("die after five wrong tries", async () => {
    await registerUser({ email: "slow@example.com", password: "StrongPass1!", firstName: "S", lastName: "L" }, {});
    const code = codeIn(sent[0]!);
    const wrong = code === "999999" ? "888888" : "999999";
    for (let i = 0; i < 5; i++) expect(await verifyEmailCode("slow@example.com", wrong)).toEqual({ status: "invalid" });
    expect(await verifyEmailCode("slow@example.com", code)).toEqual({ status: "invalid" });
    expect(await verifyEmailCode("nobody@example.com", code)).toEqual({ status: "invalid" });
  });
});
