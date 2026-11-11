import { describe, expect, it } from "vitest";
import { exportEvents, recordEvent, verifyStream } from "@/lib/audit/event-log";
import { applyRetention, getRetention, MIN_RETENTION_DAYS, setRetention } from "@/lib/audit/retention";
import { IdentityEvent } from "@/models/IdentityEvent";
import { createTestUser } from "./helpers";

const DAY = 86_400_000;

describe("audit retention", () => {
  it("keeps everything until set, and refuses too short a retention", async () => {
    expect(await getRetention()).toEqual({ accountDays: null, adminDays: null });
    await expect(setRetention({ accountDays: MIN_RETENTION_DAYS - 1, adminDays: null })).rejects.toMatchObject({ status: 400 });
    expect(await applyRetention()).toBe(0);
  });

  it("removes old events and leaves a checkpoint, so what's left still verifies", async () => {
    const { user } = await createTestUser();
    const stream = `user:${String(user._id)}`;
    for (let i = 0; i < 5; i += 1) await recordEvent({ action: "auth.signed_in", subjectId: user._id, data: { i } });
    // Make the first three old.
    const firstThree = await IdentityEvent.find({ stream }).sort({ seq: 1 }).limit(3).lean();
    await IdentityEvent.collection.updateMany({ _id: { $in: firstThree.map((e) => e._id) } }, { $set: { at: new Date(Date.now() - 400 * DAY) } });

    await setRetention({ accountDays: 365, adminDays: null });
    expect(await applyRetention()).toBe(3);
    expect(await IdentityEvent.countDocuments({ stream })).toBe(2);
    expect(await verifyStream(stream)).toMatchObject({ ok: true, events: 2 });

    // New events still chain on.
    await recordEvent({ action: "auth.signed_out", subjectId: user._id });
    expect(await verifyStream(stream)).toMatchObject({ ok: true, events: 3 });
  });

  it("still catches tampering after a purge", async () => {
    const { user } = await createTestUser();
    const stream = `user:${String(user._id)}`;
    for (let i = 0; i < 4; i += 1) await recordEvent({ action: "auth.signed_in", subjectId: user._id, data: { i } });
    const first = await IdentityEvent.findOne({ stream, seq: 1 }).lean();
    await IdentityEvent.collection.updateOne({ _id: first!._id }, { $set: { at: new Date(Date.now() - 400 * DAY) } });
    await setRetention({ accountDays: 365, adminDays: null });
    await applyRetention();
    const third = await IdentityEvent.findOne({ stream, seq: 3 }).lean();
    await IdentityEvent.collection.updateOne({ _id: third!._id }, { $set: { data: { i: 99 } } });
    expect(await verifyStream(stream)).toMatchObject({ ok: false, brokenAt: 3 });
  });
});

describe("audit export", () => {
  it("exports authentication or admin events in a window, with their hashes", async () => {
    const { user } = await createTestUser();
    await recordEvent({ action: "auth.signed_in", subjectId: user._id });
    await recordEvent({ action: "account.profile_updated", subjectId: user._id, data: { fields: ["firstName"] } });
    await recordEvent({ action: "client.updated", stream: "admin", subjectId: null, data: { changes: {} } });
    const from = new Date(Date.now() - DAY);
    const to = new Date(Date.now() + DAY);
    const auth = await exportEvents("auth", from, to);
    expect(auth.map((e) => e.action)).toEqual(["auth.signed_in"]);
    expect(auth[0]?.hash).toMatch(/^[0-9a-f]{64}$/);
    expect((await exportEvents("admin", from, to)).map((e) => e.action)).toEqual(["client.updated"]);
    expect(await exportEvents("all", from, to)).toHaveLength(3);
    expect(await exportEvents("all", new Date(Date.now() + DAY), new Date(Date.now() + 2 * DAY))).toEqual([]);
  });
});
