import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { decodeJwt } from "jose";
import type { Types } from "mongoose";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cancelMerge, completeMerge, confirmMerge, currentMerge, requestMerge } from "@/lib/account/merge";
import { mergePlan, type MergeSide } from "@/lib/account/merge-plan";
import { ACCOUNT_MERGED_EVENT, currentSubject } from "@/lib/account/merge-webhooks";
import { listEvents } from "@/lib/audit/event-log";
import { userStream } from "@/lib/audit/chain";
import { resetEnvCache } from "@/lib/config/env";
import { resetEmailProvider, setEmailProvider, type EmailMessage } from "@/lib/email/email-service";
import { spacesForSubject } from "@/lib/spaces/space-service";
import { AccountMerge } from "@/models/AccountMerge";
import { AppAccess } from "@/models/AppAccess";
import { IdentityEvent } from "@/models/IdentityEvent";
import { LinkedAccount } from "@/models/LinkedAccount";
import { MergedAccount } from "@/models/MergedAccount";
import { Organization } from "@/models/Organization";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { Passkey } from "@/models/SecurityCredential";
import { User } from "@/models/User";
import { UserEmail } from "@/models/UserEmail";
import { createTestUser } from "./helpers";

let sent: EmailMessage[] = [];
const servers: Server[] = [];

beforeEach(() => {
  sent = [];
  setEmailProvider({ send: async (message) => { sent.push(message); } });
});

afterEach(async () => {
  resetEmailProvider();
  delete process.env.ACCOUNT_MERGE_WEBHOOKS;
  resetEnvCache();
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

async function receiver() {
  const bodies: string[] = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => { bodies.push(body); res.end("{}"); });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  servers.push(server);
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/account-merged`, bodies };
}

const tokenIn = (message: EmailMessage) => new URL(message.text.match(/https?:\/\/\S+/)![0]).searchParams.get("token")!;

async function space(name: string, members: Array<[Types.ObjectId, "owner" | "admin" | "member"]>) {
  const org = await Organization.create({ name, slug: name.toLowerCase().replace(/\W+/g, "-") });
  for (const [userId, role] of members) await OrganizationMembership.create({ organizationId: org._id, userId, role });
  return org;
}

const side = (overrides: Partial<MergeSide>): MergeSide => ({ email: "a@example.com", password: false, totp: false, passkeys: 0, providers: [], verifiedEmails: [], photo: false, admin: false, spaces: [], apps: 0, ...overrides });

describe("merge plan", () => {
  it("brings across what the kept account lacks, and keeps its own where both have one", () => {
    const plan = mergePlan(
      side({ email: "keep@example.com", password: true, providers: [{ provider: "google", email: "k@gmail.com" }], spaces: [{ id: "y", name: "Home", role: "member" }] }),
      side({ email: "old@example.com", password: true, totp: true, passkeys: 2, providers: [{ provider: "google", email: "o@gmail.com" }], verifiedEmails: ["keep@example.com", "alt@example.com"], spaces: [{ id: "x", name: "Work", role: "owner" }, { id: "y", name: "Home", role: "admin" }], apps: 1, admin: true }),
    );
    expect(plan.moves).toEqual([
      "Email addresses old@example.com, alt@example.com, as confirmed additional addresses",
      "Its authenticator app and recovery codes",
      "2 passkeys",
      "Membership of Work (owner)",
      "Your admin role in Home, which you're already in as member",
      "The record of 1 app it signed in to",
    ]);
    expect(plan.drops).toEqual(expect.arrayContaining(["The other account's password (you keep this one's)", "Its Google (o@gmail.com) link (this account already has one)", "The other account's Identity admin role"]));
  });
});

describe("account merge", () => {
  it("asks, confirms from the other account's email, then moves everything and tells apps", async () => {
    const hook = await receiver();
    process.env.ACCOUNT_MERGE_WEBHOOKS = `ledger=${hook.url}`;
    resetEnvCache();
    const keep = (await createTestUser({ email: "keep@example.com" })).user;
    const old = (await createTestUser({ email: "old@example.com" })).user;
    const kId = String(keep._id);
    const oId = String(old._id);
    await Passkey.create({ userId: old._id, credentialId: "old-key", publicKey: "k", counter: 0 });
    await LinkedAccount.create({ userId: old._id, provider: "google", providerAccountId: "g-old", email: "old@gmail.com" });
    await UserEmail.create({ userId: old._id, email: "alt@example.com", verifiedAt: new Date() });
    const work = await space("Work", [[old._id, "owner"]]);
    const home = await space("Home", [[keep._id, "member"], [old._id, "admin"]]);
    await AppAccess.create({ userId: old._id, clientId: "flow", scopes: ["openid", "email"], firstUsedAt: new Date("2026-01-01"), lastUsedAt: new Date("2026-06-01") });
    await AppAccess.create({ userId: keep._id, clientId: "flow", scopes: ["openid", "profile"], firstUsedAt: new Date("2026-03-01"), lastUsedAt: new Date("2026-10-01") });

    // Typing the other account's additional address reaches its primary one.
    await requestMerge(kId, "alt@example.com");
    expect(sent.map((m) => m.to)).toEqual(["old@example.com"]);
    expect(sent[0]!.text).toContain("k***@example.com");
    const pending = await currentMerge(kId);
    expect(pending).toMatchObject({ status: "awaiting_confirmation", otherEmail: "alt@example.com", plan: null });
    await expect(completeMerge(kId, pending!.id)).rejects.toMatchObject({ code: "not_confirmed" });

    expect(await confirmMerge(tokenIn(sent[0]!))).toMatchObject({ keeperEmail: "k***@example.com" });
    await expect(confirmMerge(tokenIn(sent[0]!))).rejects.toMatchObject({ code: "token_used" });
    const review = await currentMerge(kId);
    expect(review!.plan!.moves).toEqual(expect.arrayContaining(["1 passkey", "Its Google (old@gmail.com) link", "Membership of Work (owner)"]));

    await completeMerge(kId, review!.id, { ipAddress: "203.0.113.7" });
    await expect(completeMerge(kId, review!.id)).rejects.toMatchObject({ code: "already_completed" });

    expect(await User.exists({ _id: old._id })).toBeNull();
    expect(await Passkey.countDocuments({ userId: keep._id })).toBe(1);
    expect(await LinkedAccount.findOne({ providerAccountId: "g-old" }).lean()).toMatchObject({ userId: keep._id });
    expect((await UserEmail.find({ userId: keep._id }).lean()).map((e) => [e.email, Boolean(e.verifiedAt)]).sort()).toEqual([["alt@example.com", true], ["old@example.com", true]]);
    expect(await OrganizationMembership.findOne({ organizationId: work._id }).lean()).toMatchObject({ userId: keep._id, role: "owner" });
    expect(await OrganizationMembership.find({ organizationId: home._id }).lean()).toEqual([expect.objectContaining({ userId: keep._id, role: "admin" })]);
    const flow = (await AppAccess.find({ clientId: "flow" }).lean());
    expect(flow).toHaveLength(1);
    expect(flow[0]).toMatchObject({ userId: keep._id, firstUsedAt: new Date("2026-01-01"), lastUsedAt: new Date("2026-10-01") });
    expect(flow[0]!.scopes.sort()).toEqual(["email", "openid", "profile"]);

    // Apps learn where the old sub went, and lookups by it land on the kept account.
    expect(await currentSubject(oId)).toBe(kId);
    expect((await spacesForSubject(oId)).map((s) => s.name).sort()).toEqual(["Home", "Work"]);
    expect(hook.bodies).toHaveLength(1);
    const notice = decodeJwt(hook.bodies[0]!);
    expect(notice).toMatchObject({ sub: oId, aud: "ledger", events: { [ACCOUNT_MERGED_EVENT]: { new_sub: kId } } });
    expect(await MergedAccount.findOne({ fromSub: oId }).lean()).toMatchObject({ toSub: kId, pending: [] });

    // The old account's history went with it; this one's says what happened.
    expect(await IdentityEvent.countDocuments({ stream: userStream(oId) })).toBe(0);
    const actions = (await listEvents({ stream: userStream(kId) })).events.map((e) => e.action);
    expect(actions).toEqual(["account.merged", "account.merge_confirmed", "account.merge_requested"]);
  });

  it("looks the same for an address nobody has, and can't be confirmed", async () => {
    const keep = (await createTestUser({ email: "keep@example.com" })).user;
    await requestMerge(String(keep._id), "nobody@example.com");
    expect(sent).toEqual([]);
    const pending = await currentMerge(String(keep._id));
    expect(pending).toMatchObject({ status: "awaiting_confirmation", otherEmail: "nobody@example.com" });
    await cancelMerge(String(keep._id), pending!.id);
    expect(await currentMerge(String(keep._id))).toBeNull();
    await expect(requestMerge(String(keep._id), "keep@example.com")).rejects.toMatchObject({ code: "same_account" });
  });

  it("replaces an earlier request and refuses expired or replaced links", async () => {
    const keep = (await createTestUser({ email: "keep@example.com" })).user;
    await createTestUser({ email: "old@example.com" });
    await requestMerge(String(keep._id), "old@example.com");
    const first = tokenIn(sent[0]!);
    await requestMerge(String(keep._id), "old@example.com");
    await expect(confirmMerge(first)).rejects.toMatchObject({ code: "invalid_token" });
    await AccountMerge.updateMany({ status: "awaiting_confirmation" }, { $set: { expiresAt: new Date(Date.now() - 1000) } });
    await expect(confirmMerge(tokenIn(sent[1]!))).rejects.toMatchObject({ code: "token_expired" });
  });
});
