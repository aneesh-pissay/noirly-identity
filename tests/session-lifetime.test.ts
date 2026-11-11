import { describe, expect, it } from "vitest";
import { getEnv } from "@/lib/config/env";
import { sessionPolicyFor, setSessionPolicy, validatePolicy } from "@/lib/sessions/lifetime";
import { createSession, refreshSessionExpiry, validateSession } from "@/lib/sessions/session-service";
import { IdentityEvent } from "@/models/IdentityEvent";
import { Session } from "@/models/Session";
import { createTestUser } from "./helpers";

const HOUR = 3600;
const DAY = 86_400;

describe("session lifetimes", () => {
  it("keeps Identity's defaults until the account sets its own", async () => {
    const { user } = await createTestUser();
    expect(await sessionPolicyFor(user._id)).toEqual({ idleSeconds: null, absoluteSeconds: null });
    const { session } = await createSession({ userId: String(user._id) });
    expect(session.idleTimeoutSeconds).toBeNull();
    expect(session.absoluteExpiresAt).toBeNull();
    expect(session.expiresAt.getTime() - Date.now()).toBeGreaterThan((getEnv().SESSION_TTL_SECONDS - 60) * 1000);
  });

  it("only tightens the default, within sensible limits", () => {
    expect(validatePolicy({ idleSeconds: HOUR, absoluteSeconds: DAY })).toEqual({ idleSeconds: HOUR, absoluteSeconds: DAY });
    expect(() => validatePolicy({ idleSeconds: 60, absoluteSeconds: null })).toThrow(/15 minutes/);
    expect(() => validatePolicy({ idleSeconds: null, absoluteSeconds: getEnv().SESSION_TTL_SECONDS + 1 })).toThrow(/default/);
    expect(() => validatePolicy({ idleSeconds: 2 * DAY, absoluteSeconds: DAY })).toThrow(/longer than the session/);
  });

  it("applies to new sessions: an idle limit, and an end that refreshes can't push back", async () => {
    const { user } = await createTestUser();
    const here = await createSession({ userId: String(user._id) });
    await setSessionPolicy(String(user._id), { idleSeconds: HOUR, absoluteSeconds: 8 * HOUR }, String(here.session._id));

    const { token, session } = await createSession({ userId: String(user._id) });
    expect(session.idleTimeoutSeconds).toBe(HOUR);
    expect(session.absoluteExpiresAt?.getTime()).toBe(session.expiresAt.getTime());
    expect(session.expiresAt.getTime() - Date.now()).toBeLessThanOrEqual(8 * HOUR * 1000);

    // A mobile refresh asks for 30 days; it gets no further than the limit.
    const refreshed = await refreshSessionExpiry(session._id, 30 * DAY);
    expect(refreshed?.expiresAt.getTime()).toBe(session.absoluteExpiresAt?.getTime());

    expect(await validateSession(token)).not.toBeNull();
    // Unused for over an hour: it's over.
    await Session.updateOne({ _id: session._id }, { $set: { lastActivityAt: new Date(Date.now() - HOUR * 1000 - 1000) } });
    expect(await validateSession(token)).toBeNull();
  });

  it("applies to live sessions at once, restarting this one's clock", async () => {
    const { user } = await createTestUser();
    const id = String(user._id);
    const here = await createSession({ userId: id });
    const old = await createSession({ userId: id });
    const recent = await createSession({ userId: id });
    // Signed in two days ago, and three hours ago (this one too).
    await Session.updateOne({ _id: old.session._id }, { $set: { createdAt: new Date(Date.now() - 2 * DAY * 1000) } });
    await Session.updateMany({ _id: { $in: [recent.session._id, here.session._id] } }, { $set: { createdAt: new Date(Date.now() - 3 * HOUR * 1000) } });

    await setSessionPolicy(id, { idleSeconds: null, absoluteSeconds: DAY }, String(here.session._id), { ipAddress: "203.0.113.1" });
    expect(await validateSession(old.token)).toBeNull();
    const kept = await validateSession(recent.token);
    expect(kept).not.toBeNull();
    expect(Math.abs(kept!.session.expiresAt.getTime() - (Date.now() + 21 * HOUR * 1000))).toBeLessThan(60_000);
    const mine = await validateSession(here.token);
    expect(Math.abs(mine!.session.expiresAt.getTime() - (Date.now() + DAY * 1000))).toBeLessThan(60_000);

    expect(await IdentityEvent.countDocuments({ action: "account.session_policy_changed" })).toBe(1);

    // Going back to the defaults never makes a live session last longer.
    await setSessionPolicy(id, { idleSeconds: null, absoluteSeconds: null }, String(here.session._id));
    const after = await validateSession(recent.token);
    expect(after!.session.expiresAt.getTime()).toBe(kept!.session.expiresAt.getTime());
  });
});
