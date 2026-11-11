import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { listEvents } from "@/lib/audit/event-log";
import { requestMagicLink, verifyMagicLink } from "@/lib/auth/magic-link";
import { resetEmailProvider, setEmailProvider, type EmailMessage } from "@/lib/email/email-service";
import { validateSession } from "@/lib/sessions/session-service";
import { MagicLink } from "@/models/MagicLink";
import { Mfa, SecurityChallenge } from "@/models/SecurityCredential";
import { createTestUser } from "./helpers";

let sent: EmailMessage[] = [];

beforeEach(() => {
  sent = [];
  setEmailProvider({ send: async (message) => { sent.push(message); } });
});

afterEach(() => resetEmailProvider());

const CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
const linkIn = (message: EmailMessage) => new URL(message.text.match(/https?:\/\/\S+/)![0]);

describe("emailed sign-in links", () => {
  it("signs in once, only in the browser that asked, and goes back where it was going", async () => {
    const { user } = await createTestUser();
    const { browserSecret } = await requestMagicLink(user.email, "/consent?client_id=app", { ipAddress: "203.0.113.7", userAgent: CHROME });
    expect(sent).toHaveLength(1);
    expect(sent[0]!.text).toContain("Chrome on Windows");
    const url = linkIn(sent[0]!);
    expect(url.pathname).toBe("/magic-link");
    expect(url.searchParams.get("return_to")).toBe("/consent?client_id=app");
    const token = url.searchParams.get("token")!;

    // Another browser (or a mail scanner) gets nothing and doesn't use it up.
    await expect(verifyMagicLink(token, null)).rejects.toMatchObject({ code: "other_browser" });
    await expect(verifyMagicLink(token, "someone-elses-secret-xxxxxxxxxxxxxxxxxxxxxxxx")).rejects.toMatchObject({ code: "other_browser" });

    const result = await verifyMagicLink(token, browserSecret, { ipAddress: "203.0.113.7", userAgent: CHROME });
    expect(result.returnTo).toBe("/consent?client_id=app");
    expect(await validateSession(result.sessionToken)).not.toBeNull();
    await expect(verifyMagicLink(token, browserSecret)).rejects.toMatchObject({ code: "token_used" });

    const actions = (await listEvents({ action: "auth." })).events.map((e) => [e.action, e.data]);
    expect(actions).toEqual([["auth.signed_in", { methods: ["magic_link"] }], ["auth.magic_link_sent", null]]);
  });

  it("answers the same for addresses with no account, or not yet confirmed, and sends nothing", async () => {
    await createTestUser({ email: "pending@example.com", status: "pending_verification" });
    const unknown = await requestMagicLink("nobody@example.com", null);
    const pending = await requestMagicLink("pending@example.com", null);
    expect(unknown.browserSecret).toHaveLength(43);
    expect(pending.browserSecret).toHaveLength(43);
    expect(sent).toEqual([]);
    expect(await MagicLink.countDocuments()).toBe(0);
  });

  it("keeps one secret per browser, so asking twice doesn't break the first link", async () => {
    const { user } = await createTestUser();
    const first = await requestMagicLink(user.email, null);
    const second = await requestMagicLink(user.email, null, {}, first.browserSecret);
    expect(second.browserSecret).toBe(first.browserSecret);
    const token = linkIn(sent[0]!).searchParams.get("token")!;
    await expect(verifyMagicLink(token, first.browserSecret)).resolves.toMatchObject({ returnTo: "/account" });
  });

  it("refuses expired links and limits how many one address gets", async () => {
    const { user } = await createTestUser();
    const { browserSecret } = await requestMagicLink(user.email, null);
    await MagicLink.updateMany({}, { $set: { expiresAt: new Date(Date.now() - 1000) } });
    await expect(verifyMagicLink(linkIn(sent[0]!).searchParams.get("token")!, browserSecret)).rejects.toMatchObject({ code: "token_expired" });
    for (let i = 0; i < 6; i++) await requestMagicLink(user.email, null);
    expect(sent).toHaveLength(5);
  });

  it("still asks for the second factor on accounts that have one", async () => {
    const { user } = await createTestUser();
    await Mfa.create({ userId: user._id, enabled: true, secret: "x" });
    const { browserSecret } = await requestMagicLink(user.email, null);
    await expect(verifyMagicLink(linkIn(sent[0]!).searchParams.get("token")!, browserSecret)).rejects.toMatchObject({ code: "mfa_required" });
    expect((await SecurityChallenge.findOne({ userId: user._id }).lean())?.method).toBe("magic_link");
  });
});
