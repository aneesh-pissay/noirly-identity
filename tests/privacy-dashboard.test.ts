import { describe, expect, it } from "vitest";
import { noteTokenIssued, removeAppAccess, listAppAccess } from "@/lib/account/app-access";
import { privacySummary } from "@/lib/account/privacy";
import { setRetention } from "@/lib/audit/retention";
import { recordEvent } from "@/lib/audit/event-log";
import { noteSignIn } from "@/lib/security/risk";
import { createSession } from "@/lib/sessions/session-service";
import { createSpace } from "@/lib/spaces/space-service";
import { UserEmail } from "@/models/UserEmail";
import { createTestClient, createTestUser } from "./helpers";

describe("the privacy dashboard", () => {
  it("says what Identity holds, how much, why and how long", async () => {
    const { user } = await createTestUser();
    const id = String(user._id);
    await UserEmail.create({ userId: user._id, email: "work@example.com", verifiedAt: new Date() });
    await createSession({ userId: id });
    await noteSignIn(id, { deviceId: "device-000000000001", place: "Pune, IN" });
    await createSpace({ ownerId: id, name: "Home" });
    await recordEvent({ action: "auth.signed_in", subjectId: id });
    const { client } = await createTestClient();
    await noteTokenIssued(id, client.clientId, "openid email");

    const summary = Object.fromEntries((await privacySummary(id)).map((c) => [c.id, c]));
    expect(summary.emails?.count).toBe(2);
    expect(summary.sessions?.count).toBe(1);
    expect(summary.history).toMatchObject({ count: 1, kept: "One year" });
    expect(summary.spaces?.count).toBe(1);
    expect(summary.apps?.count).toBe(1);
    expect(summary.activity).toMatchObject({ kept: "Until you delete your account" });
    expect(summary.activity!.count).toBeGreaterThanOrEqual(1);
    expect(summary.phone?.count).toBe(0);

    // Retention shows; removing an app's consent shows too.
    await setRetention({ accountDays: 365, adminDays: null });
    expect(Object.fromEntries((await privacySummary(id)).map((c) => [c.id, c])).activity?.kept).toBe("365 days, then removed");
    await removeAppAccess(id, client.clientId);
    expect(await listAppAccess(id)).toEqual([]);
    expect(Object.fromEntries((await privacySummary(id)).map((c) => [c.id, c])).apps?.count).toBe(0);
  });
});
