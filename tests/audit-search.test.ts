import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { deleteAlertRule, listAlertRules, saveAlertRule } from "@/lib/audit/alert-rules";
import { listEvents, recordEvent } from "@/lib/audit/event-log";
import { resetEmailProvider, setEmailProvider, type EmailMessage } from "@/lib/email/email-service";
import { createTestUser } from "./helpers";

let sent: EmailMessage[] = [];
beforeEach(() => { sent = []; setEmailProvider({ send: async (m) => { sent.push(m); } }); });
afterEach(() => resetEmailProvider());

describe("admin audit search", () => {
  it("filters by actor, app, address and time window, as well as action and account", async () => {
    const { user } = await createTestUser();
    const { user: admin } = await createTestUser({ email: "admin@example.com" });
    await recordEvent({ action: "auth.signed_in", subjectId: user._id, clientId: "noirly-crm", request: { ipAddress: "203.0.113.5" } });
    await recordEvent({ action: "auth.signed_in", subjectId: user._id, clientId: "noirly-docs", request: { ipAddress: "198.51.100.9" } });
    await recordEvent({ action: "client.updated", stream: "admin", actorId: admin._id, subjectId: null, clientId: "noirly-crm" });

    expect((await listEvents({ clientId: "noirly-crm" })).events.map((e) => e.action).sort()).toEqual(["auth.signed_in", "client.updated"]);
    expect((await listEvents({ ipAddress: "198.51.100.9" })).events).toHaveLength(1);
    expect((await listEvents({ actorId: String(admin._id) })).events.map((e) => e.action)).toEqual(["client.updated"]);
    expect((await listEvents({ action: "auth.", subjectId: String(user._id) })).events).toHaveLength(2);
    expect((await listEvents({ from: new Date(Date.now() + 60_000) })).events).toEqual([]);
    expect((await listEvents({ to: new Date(Date.now() + 60_000) })).events).toHaveLength(3);
  });
});

describe("alerts on chosen events", () => {
  it("email the rule's recipients for matching actions, in any stream, and not others", async () => {
    const { user: admin } = await createTestUser({ email: "admin@example.com" });
    const { user } = await createTestUser();
    await saveAlertRule(String(admin._id), { name: "Lockouts", actions: ["account.contained", "client."], emails: ["soc@example.com", "lead@example.com"] });
    await recordEvent({ action: "client.deleted", stream: "admin", actorId: admin._id, subjectId: null, clientId: "old-app" });
    await recordEvent({ action: "account.profile_updated", subjectId: user._id });
    const alerts = sent.filter((m) => m.subject.startsWith("[Noirly audit]"));
    expect(alerts.map((m) => m.to).sort()).toEqual(["lead@example.com", "soc@example.com"]);
    expect(alerts[0]?.subject).toBe("[Noirly audit] Lockouts: client.deleted");
  });

  it("validate actions and recipients, and can be turned off or deleted", async () => {
    const { user: admin } = await createTestUser({ email: "admin@example.com" });
    await expect(saveAlertRule(String(admin._id), { name: "Bad", actions: ["nope.nothing"], emails: ["a@example.com"] })).rejects.toMatchObject({ status: 400 });
    await expect(saveAlertRule(String(admin._id), { name: "Bad", actions: ["auth."], emails: ["not-an-email"] })).rejects.toMatchObject({ status: 400 });
    const rule = await saveAlertRule(String(admin._id), { name: "Sign-ins", actions: ["auth.signed_in"], emails: ["soc@example.com"] });
    await saveAlertRule(String(admin._id), { ...rule, enabled: false });
    await recordEvent({ action: "auth.signed_in", subjectId: admin._id });
    expect(sent.filter((m) => m.subject.startsWith("[Noirly audit]"))).toEqual([]);
    await deleteAlertRule(rule.id);
    expect(await listAlertRules()).toEqual([]);
  });
});
