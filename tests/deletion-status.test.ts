import { afterEach, describe, expect, it, vi } from "vitest";
import { listDeletionStatus, retryDeletionNow } from "@/lib/account/deletion-status";
import { notifyAccountDeleted, retryPendingDeletionNotices } from "@/lib/account/deletion-webhooks";
import { listEvents } from "@/lib/audit/event-log";
import { resetEnvCache } from "@/lib/config/env";
import { createTestUser } from "./helpers";

afterEach(() => {
  vi.restoreAllMocks();
  delete process.env.ACCOUNT_DELETION_WEBHOOKS;
  resetEnvCache();
});

describe("coordinated deletion status", () => {
  it("shows which apps confirmed, retries, gives up, and retries now on request", async () => {
    process.env.ACCOUNT_DELETION_WEBHOOKS = "noirly-flow=https://flow.example.com/deleted,noirly-ledger=https://ledger.example.com/deleted";
    resetEnvCache();
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (url) =>
      new Response("{}", { status: String(url).includes("flow") ? 200 : 503 }));

    await notifyAccountDeleted("sub-1");
    let [status] = await listDeletionStatus();
    expect(status).toMatchObject({ sub: "sub-1", state: "pending" });
    expect(status!.delivered.map((d) => d.clientId)).toEqual(["noirly-flow"]);
    expect(status!.pending).toMatchObject([{ clientId: "noirly-ledger", attempts: 1, lastError: "HTTP 503" }]);

    // Retries run out: the app is marked as never confirming.
    expect(await retryPendingDeletionNotices(2)).toBe(0);
    [status] = await listDeletionStatus({ state: "failed" });
    expect(status!.failed).toMatchObject([{ clientId: "noirly-ledger", attempts: 2 }]);
    expect(await listDeletionStatus({ state: "pending" })).toEqual([]);

    // The app is back; an admin retries now.
    fetchMock.mockImplementation(async () => new Response("{}", { status: 200 }));
    const { user: admin } = await createTestUser({ email: "admin@example.com" });
    const after = await retryDeletionNow("sub-1", String(admin._id));
    expect(after.state).toBe("confirmed");
    expect(after.delivered.map((d) => d.clientId).sort()).toEqual(["noirly-flow", "noirly-ledger"]);
    expect((await listEvents({ action: "admin.deletion_retried" })).events).toHaveLength(1);
    await expect(retryDeletionNow("nobody", String(admin._id))).rejects.toMatchObject({ status: 404 });
  });
});
