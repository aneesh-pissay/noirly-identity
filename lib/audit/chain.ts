/**
 * The identity event log: sign-ins, security changes and admin actions,
 * each written once and never changed. Events are kept in streams (one per
 * account, one for admin actions, one for the system), and each event in a
 * stream carries the hash of the one before it. An event edited, removed or
 * slipped in later, even straight in the database, breaks the chain and
 * shows up when the stream is checked.
 */

export const IDENTITY_ACTIONS = [
  "account.registered",
  "account.email_verified",
  "account.profile_updated",
  "account.identity_linked",
  "account.identity_unlinked",
  "account.deleted",
  "account.merge_requested",
  "account.merge_confirmed",
  "account.merge_cancelled",
  "account.merged",
  "account.session_policy_changed",
  "account.contained",
  "account.unlocked",
  "account.locked",
  "account.frozen",
  "account.unfreeze_scheduled",
  "account.unfreeze_cancelled",
  "account.closing",
  "account.closure_undone",
  "account.data_exported",
  "admin.deletion_retried",
  "email.added",
  "email.verified",
  "email.removed",
  "email.primary_changed",
  "email.change_undone",
  "phone.verification_sent",
  "phone.verified",
  "phone.removed",
  "auth.signed_in",
  "auth.sign_in_failed",
  "auth.signed_out",
  "auth.magic_link_sent",
  "auth.stepped_up",
  "auth.sessions_signed_out",
  "auth.app_signed_out",
  "auth.unusual_sign_in",
  "password.changed",
  "password.reset",
  "password.set",
  "password.removed",
  "password.breach_detected",
  "mfa.totp_enabled",
  "mfa.totp_disabled",
  "mfa.recovery_code_used",
  "mfa.recovery_codes_replaced",
  "mfa.requirement_changed",
  "recovery.started",
  "recovery.cancelled",
  "recovery.completed",
  "recovery.review_approved",
  "recovery.review_denied",
  "recovery_method.added",
  "recovery_method.removed",
  "passkey.added",
  "passkey.removed",
  "passkey.renamed",
  "oauth.consent_granted",
  "oauth.access_removed",
  "oauth.refresh_reuse_detected",
  "client.registered",
  "client.updated",
  "client.deleted",
  "signing_key.rotated",
  "signing_key.removed",
  "resource.saved",
  "audit.exported",
  "audit.retention_changed",
  "authz.role_saved",
  "authz.role_deleted",
  "authz.assigned",
  "authz.unassigned",
  "authz.attributes_set",
  "authz.elevation_requested",
  "authz.elevation_approved",
  "authz.elevation_denied",
  "authz.service_account_created",
  "authz.service_account_disabled",
  "sso.provider_saved",
  "sso.provider_deleted",
  "sso.enforcement_changed",
  "sso.break_glass_used",
  "sso.user_provisioned",
  "sso.groups_mapped",
  "sso.certificate_expiring",
  "sso.certificate_rotated",
  "directory.member_deactivated",
  "directory.member_reactivated",
  "directory.scim_token_created",
  "directory.scim_token_revoked",
  "directory.user_provisioned",
  "directory.user_updated",
  "directory.group_synced",
  "directory.bulk_action",
] as const;
export type IdentityAction = (typeof IDENTITY_ACTIONS)[number];

/** How someone proved who they are, as recorded on a sign-in. */
export type SignInMethod = "password" | "google" | "apple" | "microsoft" | "github" | "passkey" | "totp" | "recovery_code" | "mobile_browser" | "magic_link" | "email_code" | "sso";

/** One account's events, admin actions, or what the system did on its own (deleted accounts). */
export type EventStream = `user:${string}` | `org:${string}` | "admin" | "system";

export const ADMIN_STREAM = "admin" as const;
export const SYSTEM_STREAM = "system" as const;

export function userStream(userId: string): EventStream {
  return `user:${userId}`;
}

/** One organization's own log: its access control changes (lib/authz). */
export function orgStream(organizationId: string): EventStream {
  return `org:${organizationId}`;
}

export function isEventStream(value: string): value is EventStream {
  return value === ADMIN_STREAM || value === SYSTEM_STREAM || /^(user|org):[a-f0-9]{24}$/.test(value);
}

/** The hash before a stream's first event. */
export const GENESIS_HASH = "0".repeat(64);

/** What's hashed: everything an event says. */
export type EventFields = {
  stream: string;
  seq: number;
  at: string;
  action: string;
  actorId: string | null;
  subjectId: string | null;
  clientId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  data: unknown;
};

/** JSON with object keys sorted, so the same event always reads the same. Dates as ISO strings; undefined left out. */
export function canonicalJson(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (Array.isArray(value)) return `[${value.map((v) => (v === undefined ? "null" : canonicalJson(v))).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    // ObjectIds and the like read as their string.
    if (typeof (record as { toHexString?: unknown }).toHexString === "function") return JSON.stringify(String(value));
    const keys = Object.keys(record).filter((k) => record[k] !== undefined).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(record[k])}`).join(",")}}`;
  }
  if (typeof value === "number" && !Number.isFinite(value)) return "null";
  return JSON.stringify(value);
}

/** The text an event's hash is taken of: the previous hash, then the event. */
export function hashInput(prevHash: string, fields: EventFields) {
  return `${prevHash}\n${canonicalJson(fields)}`;
}

export type ChainEvent = EventFields & { prevHash: string; hash: string };

export type ChainCheck =
  | { ok: true; events: number; lastHash: string }
  | { ok: false; events: number; brokenAt: number; reason: string };

/**
 * Walks a stream's events, oldest first, a page at a time: each must follow
 * the last by one, point at its hash, and hash to what it says.
 */
export class ChainChecker {
  private expectedSeq = 1;
  private prevHash = GENESIS_HASH;
  private count = 0;
  private failure: { brokenAt: number; reason: string } | null = null;

  /** `from`: a retention checkpoint (the last removed event), to verify what's left from there. */
  constructor(private readonly hash: (text: string) => string, from?: { seq: number; hash: string } | null) {
    if (from) {
      this.expectedSeq = from.seq + 1;
      this.prevHash = from.hash;
    }
  }

  add(event: ChainEvent) {
    if (this.failure) return;
    if (event.seq !== this.expectedSeq) {
      this.failure = { brokenAt: this.expectedSeq, reason: event.seq > this.expectedSeq ? `Event ${this.expectedSeq} is missing` : `Event ${event.seq} appears twice` };
      return;
    }
    if (event.prevHash !== this.prevHash) {
      this.failure = { brokenAt: event.seq, reason: `Event ${event.seq} doesn't follow the one before it` };
      return;
    }
    const { prevHash, hash, ...fields } = event;
    if (this.hash(hashInput(prevHash, fields)) !== hash) {
      this.failure = { brokenAt: event.seq, reason: `Event ${event.seq} was changed after it was written` };
      return;
    }
    this.prevHash = hash;
    this.expectedSeq += 1;
    this.count += 1;
  }

  result(): ChainCheck {
    if (this.failure) return { ok: false, events: this.count, ...this.failure };
    return { ok: true, events: this.count, lastHash: this.prevHash };
  }
}

export type IdentityEventView = {
  stream: string;
  seq: number;
  at: string;
  action: string;
  actorId: string | null;
  subjectId: string | null;
  clientId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  data: unknown;
  hash: string;
};
