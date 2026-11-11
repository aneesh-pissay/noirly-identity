import { ADMIN_STREAM, SYSTEM_STREAM, userStream } from "@/lib/audit/chain";
import { verifyStream } from "@/lib/audit/event-log";
import { AuditAlertRule } from "@/lib/audit/alert-rules";
import { getRetention } from "@/lib/audit/retention";
import { DeletedAccount } from "@/models/DeletedAccount";
import { FactorRecovery } from "@/models/FactorRecovery";
import { Mfa, Passkey } from "@/models/SecurityCredential";
import { Session } from "@/models/Session";
import { SigningKey } from "@/models/SigningKey";
import { User } from "@/models/User";

/**
 * Evidence for a compliance review (docs/compliance/CONTROLS.md), collected
 * live: audit chain integrity, signing key state, retention, second-step
 * coverage (everyone, and admins), locked accounts, deletion notices and
 * recovery requests. Every check has `ok`, so a reviewer sees at a glance
 * which controls are holding. Contains counts and ids only, no personal data.
 */

const KEY_MAX_AGE_DAYS = 180;
const USER_STREAM_SAMPLE = 25;

type Check<T> = T & { ok: boolean };

export type Evidence = {
  collectedAt: string;
  auditChains: Check<{ streams: Array<{ stream: string; ok: boolean; events: number; reason?: string }> }>;
  signingKeys: Check<{ active: { kid: string; ageDays: number } | null; next: number; retired: number; maxAgeDays: number }>;
  retention: Check<{ accountDays: number | null; adminDays: number | null; minimumDays: number }>;
  secondStep: Check<{ users: number; withSecondStep: number; admins: number; adminsWithSecondStep: number; adminsWithout: string[] }>;
  lockedAccounts: Check<{ count: number }>;
  deletionNotices: Check<{ pending: number; failed: number }>;
  recoveries: Check<{ pending: number }>;
  alertRules: Check<{ enabled: number }>;
  sessions: Check<{ active: number }>;
};

const days = (from: Date, to = Date.now()) => Math.floor((to - from.getTime()) / 86_400_000);

export async function collectEvidence(): Promise<Evidence> {
  const now = new Date();

  // Admin and system chains in full, and the most recently active accounts' chains.
  const recent = await Session.find({}).sort({ createdAt: -1 }).limit(200).distinct("userId");
  const streams = [ADMIN_STREAM, SYSTEM_STREAM, ...recent.slice(0, USER_STREAM_SAMPLE).map((id) => userStream(String(id)))];
  const checks = [];
  for (const stream of streams) {
    const r = await verifyStream(stream);
    checks.push({ stream, ok: r.ok, events: r.events, ...(r.ok ? {} : { reason: r.reason }) });
  }

  const keys = await SigningKey.find({}).select("kid state activatedAt createdAt").lean();
  const active = keys.find((k) => k.state === "active");
  const activeAge = active ? days(active.activatedAt ?? active.createdAt) : null;

  const retention = await getRetention();
  const { MIN_RETENTION_DAYS } = await import("@/lib/audit/retention");

  const [mfaUsers, passkeyUsers] = await Promise.all([Mfa.distinct("userId", { enabled: true }), Passkey.distinct("userId")]);
  const covered = new Set([...mfaUsers, ...passkeyUsers].map(String));
  const users = await User.countDocuments({});
  const admins = await User.find({ roles: "admin" }).select("_id").lean();
  const adminsWithout = admins.filter((a) => !covered.has(String(a._id))).map((a) => String(a._id));

  const [locked, pendingDeletions, failedDeletions, recoveries, rules, activeSessions] = await Promise.all([
    User.countDocuments({ lockedAt: { $ne: null } }),
    DeletedAccount.countDocuments({ "pending.0": { $exists: true } }),
    DeletedAccount.countDocuments({ "failed.0": { $exists: true } }),
    FactorRecovery.countDocuments({ status: "pending" }),
    AuditAlertRule.countDocuments({ enabled: true }),
    Session.countDocuments({ revokedAt: null, expiresAt: { $gt: now } }),
  ]);

  return {
    collectedAt: now.toISOString(),
    auditChains: { ok: checks.every((c) => c.ok), streams: checks },
    signingKeys: {
      ok: Boolean(active) && (activeAge ?? 0) <= KEY_MAX_AGE_DAYS,
      active: active ? { kid: active.kid, ageDays: activeAge! } : null,
      next: keys.filter((k) => k.state === "next").length,
      retired: keys.filter((k) => k.state === "retired").length,
      maxAgeDays: KEY_MAX_AGE_DAYS,
    },
    retention: {
      ok: [retention.accountDays, retention.adminDays].every((d) => d === null || d >= MIN_RETENTION_DAYS),
      ...retention,
      minimumDays: MIN_RETENTION_DAYS,
    },
    secondStep: {
      ok: adminsWithout.length === 0,
      users,
      withSecondStep: covered.size,
      admins: admins.length,
      adminsWithSecondStep: admins.length - adminsWithout.length,
      adminsWithout,
    },
    lockedAccounts: { ok: true, count: locked },
    deletionNotices: { ok: failedDeletions === 0, pending: pendingDeletions, failed: failedDeletions },
    recoveries: { ok: true, pending: recoveries },
    alertRules: { ok: rules > 0, enabled: rules },
    sessions: { ok: true, active: activeSessions },
  };
}
