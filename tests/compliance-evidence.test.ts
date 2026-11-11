import { describe, expect, it } from "vitest";
import { recordEvent } from "@/lib/audit/event-log";
import { saveAlertRule } from "@/lib/audit/alert-rules";
import { collectEvidence } from "@/lib/compliance/evidence";
import { ensureSigningKeys } from "@/lib/oidc/keys";
import { createSession } from "@/lib/sessions/session-service";
import { IdentityEvent } from "@/models/IdentityEvent";
import { Mfa } from "@/models/SecurityCredential";
import { User } from "@/models/User";
import { createTestUser } from "./helpers";

describe("compliance evidence", () => {
  it("reports each control, and fails the ones that aren't holding", async () => {
    await ensureSigningKeys();
    const { user: admin } = await createTestUser({ email: "admin@example.com" });
    await User.updateOne({ _id: admin._id }, { $set: { roles: ["user", "admin"] } });
    const { user } = await createTestUser();
    await createSession({ userId: String(user._id) });
    await recordEvent({ action: "auth.signed_in", subjectId: user._id });
    await recordEvent({ action: "client.updated", stream: "admin", actorId: admin._id, subjectId: null, clientId: "app" });

    let evidence = await collectEvidence();
    expect(evidence.auditChains.ok).toBe(true);
    expect(evidence.auditChains.streams.map((s) => s.stream)).toContain(`user:${String(user._id)}`);
    expect(evidence.signingKeys).toMatchObject({ ok: true, active: { ageDays: 0 } });
    expect(evidence.secondStep).toMatchObject({ ok: false, admins: 1, adminsWithout: [String(admin._id)] });
    expect(evidence.alertRules.ok).toBe(false);
    expect(evidence.retention.ok).toBe(true);

    // Fix them; then tamper with the chain.
    await Mfa.create({ userId: admin._id, enabled: true, secret: "sealed" });
    await saveAlertRule(String(admin._id), { name: "Admin", actions: ["client."], emails: ["soc@example.com"] });
    await IdentityEvent.collection.updateOne({ stream: `user:${String(user._id)}` }, { $set: { action: "auth.signed_out" } });
    evidence = await collectEvidence();
    expect(evidence.secondStep).toMatchObject({ ok: true, adminsWithSecondStep: 1 });
    expect(evidence.alertRules.ok).toBe(true);
    expect(evidence.auditChains.ok).toBe(false);
    expect(JSON.stringify(evidence)).not.toContain("example.com");
  });
});
