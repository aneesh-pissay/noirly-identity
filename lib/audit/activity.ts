import type { IdentityAction, SignInMethod } from "@/lib/audit/chain";
import { PROVIDER_LABEL, type Provider } from "@/lib/account/sign-in-methods";

/**
 * Security activity: an account's own event log, read back to its owner as
 * plain sentences, with sign-ins from a device it hasn't used before and
 * anything suspicious picked out.
 */

export const ACTIVITY_KINDS = ["sign_in", "security", "account", "apps"] as const;
export type ActivityKind = (typeof ACTIVITY_KINDS)[number];

export const ACTIVITY_KIND_LABEL: Record<ActivityKind, string> = {
  sign_in: "Sign-ins",
  security: "Security changes",
  account: "Account",
  apps: "Apps",
};

const KIND_OF: Record<IdentityAction, ActivityKind | null> = {
  "account.registered": "account",
  "account.email_verified": "account",
  "account.profile_updated": "account",
  "account.identity_linked": "security",
  "account.identity_unlinked": "security",
  "account.deleted": null,
  "account.merge_requested": "security",
  "account.merge_confirmed": "security",
  "account.merge_cancelled": "security",
  "account.merged": "security",
  "account.session_policy_changed": "security",
  "account.contained": "security",
  "account.unlocked": "security",
  "account.locked": "security",
  "account.frozen": "security",
  "account.unfreeze_scheduled": "security",
  "account.unfreeze_cancelled": "security",
  "account.closing": "security",
  "account.closure_undone": "security",
  "account.data_exported": "account",
  "email.added": "account",
  "email.verified": "account",
  "email.removed": "account",
  "email.primary_changed": "security",
  "email.change_undone": "security",
  "phone.verification_sent": "account",
  "phone.verified": "account",
  "phone.removed": "account",
  "auth.signed_in": "sign_in",
  "auth.sign_in_failed": "sign_in",
  "auth.signed_out": "sign_in",
  "auth.magic_link_sent": "sign_in",
  "auth.stepped_up": "sign_in",
  "auth.sessions_signed_out": "security",
  "auth.app_signed_out": "apps",
  "auth.unusual_sign_in": "security",
  "password.changed": "security",
  "password.reset": "security",
  "password.set": "security",
  "password.removed": "security",
  "password.breach_detected": "security",
  "mfa.totp_enabled": "security",
  "mfa.totp_disabled": "security",
  "mfa.recovery_code_used": "security",
  "mfa.recovery_codes_replaced": "security",
  "mfa.requirement_changed": "security",
  "recovery.started": "security",
  "recovery.cancelled": "security",
  "recovery.completed": "security",
  "recovery.review_approved": "security",
  "recovery.review_denied": "security",
  "recovery_method.added": "security",
  "recovery_method.removed": "security",
  "passkey.added": "security",
  "passkey.removed": "security",
  "passkey.renamed": "security",
  "oauth.consent_granted": "apps",
  "oauth.access_removed": "apps",
  "oauth.refresh_reuse_detected": "security",
  // Admin actions never land in an account's own stream.
  "client.registered": null,
  "client.updated": null,
  "client.deleted": null,
  "signing_key.rotated": null,
  "signing_key.removed": null,
  "resource.saved": null,
  "audit.exported": null,
  "audit.retention_changed": null,
  "authz.role_saved": null,
  "authz.role_deleted": null,
  "authz.assigned": "security",
  "authz.unassigned": "security",
  "authz.attributes_set": null,
  "authz.elevation_requested": "security",
  "authz.elevation_approved": "security",
  "authz.elevation_denied": "security",
  "authz.service_account_created": null,
  "authz.service_account_disabled": null,
  "admin.deletion_retried": null,
  "sso.provider_saved": null,
  "sso.provider_deleted": null,
  "sso.enforcement_changed": null,
  "sso.break_glass_used": "security",
  "sso.user_provisioned": null,
  "sso.groups_mapped": null,
  "sso.certificate_expiring": null,
  "sso.certificate_rotated": null,
  "directory.member_deactivated": null,
  "directory.member_reactivated": null,
  "directory.scim_token_created": null,
  "directory.scim_token_revoked": null,
  "directory.user_provisioned": null,
  "directory.user_updated": null,
  "directory.group_synced": null,
  "directory.bulk_action": null,
};

export function activityKind(action: string): ActivityKind | null {
  return KIND_OF[action as IdentityAction] ?? null;
}

/** The actions that make up a kind, for filtering the log. */
export function actionsOf(kind: ActivityKind): IdentityAction[] {
  return (Object.keys(KIND_OF) as IdentityAction[]).filter((action) => KIND_OF[action] === kind);
}

const METHOD_LABEL: Record<SignInMethod, string> = {
  password: "password",
  google: "Google",
  apple: "Apple",
  microsoft: "Microsoft",
  github: "GitHub",
  passkey: "a passkey",
  totp: "an authenticator code",
  recovery_code: "a recovery code",
  mobile_browser: "approval from a signed-in browser",
  magic_link: "an emailed sign-in link",
  email_code: "an emailed code",
  sso: "your organization's sign-in",
};

function listOf(words: string[]) {
  return words.length <= 1 ? (words[0] ?? "") : `${words.slice(0, -1).join(", ")} and ${words.at(-1)}`;
}

const FIELD_LABEL: Record<string, string> = { firstName: "first name", lastName: "last name", displayName: "display name", avatarUrl: "photo", phoneNumber: "phone number", locale: "language", zoneinfo: "time zone", accessibility: "accessibility settings" };

type Data = Record<string, unknown> | null;

/** What happened, as a sentence its owner reads. */
export function describeActivity(action: string, data: Data): string {
  const d = data ?? {};
  switch (action as IdentityAction) {
    case "auth.signed_in": {
      const methods = Array.isArray(d.methods) ? (d.methods as SignInMethod[]).map((m) => METHOD_LABEL[m] ?? m) : [];
      return methods.length ? `Signed in with ${listOf(methods)}` : "Signed in";
    }
    case "auth.sign_in_failed":
      return d.reason === "wrong_password" ? "Someone tried to sign in with the wrong password" : "A sign-in failed";
    case "auth.signed_out":
      return "Signed out";
    case "auth.stepped_up": {
      const methods = Array.isArray(d.methods) ? (d.methods as SignInMethod[]) : [];
      const last = methods.at(-1);
      return last ? `Confirmed it was you with ${METHOD_LABEL[last] ?? last}, for an app that asked` : "Confirmed it was you, for an app that asked";
    }
    case "auth.sessions_signed_out": {
      const count = typeof d.count === "number" ? d.count : 0;
      return `Signed out ${count === 1 ? "a device" : `${count} devices`} from the account page`;
    }
    case "auth.unusual_sign_in":
      return `Unusual sign-in: ${((d.signals as string[] | undefined) ?? []).map((x) => x.replace(/_/g, " ")).join(", ")}`;
    case "auth.app_signed_out":
      return d.everywhere ? "Signed out of an app on every device" : "Signed out of an app on one device";
    case "auth.magic_link_sent":
      return "Sign-in link and code emailed";
    case "password.breach_detected":
      return "Your password was found in a data breach elsewhere";
    case "account.registered":
      return d.method === "google" ? "Account created with Google" : "Account created";
    case "account.email_verified":
      return typeof d.email === "string" ? `Email address ${d.email} verified` : "Email address verified";
    case "account.profile_updated": {
      const fields = Array.isArray(d.fields) ? (d.fields as string[]).map((f) => FIELD_LABEL[f] ?? f) : [];
      return fields.length ? `Changed ${listOf(fields)}` : "Profile updated";
    }
    case "account.merge_requested":
      return typeof d.email === "string" ? `Asked to merge the account at ${d.email} into this one` : "Asked to merge another account into this one";
    case "account.merge_confirmed":
      return typeof d.email === "string" ? `The account at ${d.email} confirmed the merge` : "The other account confirmed the merge";
    case "account.merge_cancelled":
      return "Account merge cancelled";
    case "recovery.review_approved":
      return "Account recovery approved after review";
    case "recovery.review_denied":
      return "Account recovery declined after review";
    case "recovery_method.added":
      return typeof d.email === "string" ? `Recovery address ${d.email} added` : "Recovery address added";
    case "recovery_method.removed":
      return typeof d.email === "string" ? `Recovery address ${d.email} removed` : "Recovery address removed";
    case "account.contained":
      return "Account locked by Noirly to protect it: signed out everywhere";
    case "account.locked":
      return "Account locked by Noirly";
    case "account.frozen":
      return "You froze your account: signed out everywhere";
    case "account.unfreeze_scheduled":
      return typeof d.unlockAt === "string" ? `Unfreeze confirmed: the account unfreezes ${new Date(d.unlockAt).toLocaleString()}` : "Unfreeze confirmed";
    case "account.unfreeze_cancelled":
      return "Unfreeze stopped: the account stays frozen";
    case "account.closing":
      return typeof d.deleteAfter === "string" ? `Account closed; deleted for good ${new Date(d.deleteAfter).toLocaleDateString()} unless undone` : "Account closed";
    case "account.data_exported":
      return "Asked for a copy of your data";
    case "account.closure_undone":
      return "Account closure undone";
    case "account.unlocked":
      return "Account unlocked";
    case "account.session_policy_changed":
      return "Changed how long sessions last";
    case "account.merged":
      return typeof d.email === "string" ? `The account at ${d.email} was merged into this one` : "Another account was merged into this one";
    case "email.added":
      return typeof d.email === "string" ? `Added ${d.email}, waiting to be confirmed` : "Email address added";
    case "email.verified":
      return typeof d.email === "string" ? `Confirmed ${d.email}` : "Email address confirmed";
    case "email.removed":
      return typeof d.email === "string" ? `Removed ${d.email}` : "Email address removed";
    case "email.primary_changed":
      return typeof d.to === "string" ? `Primary email address changed to ${d.to}` : "Primary email address changed";
    case "phone.verification_sent":
      return typeof d.phone === "string" ? `Verification code texted to ${d.phone}` : "Verification code texted";
    case "phone.verified":
      return typeof d.phone === "string" ? `Phone number ${d.phone} verified` : "Phone number verified";
    case "phone.removed":
      return typeof d.phone === "string" ? `Phone number ${d.phone} removed` : "Phone number removed";
    case "email.change_undone":
      return typeof d.restored === "string" ? `Email change undone: ${d.restored} is primary again and every session was signed out` : "Email change undone and every session signed out";
    case "account.identity_linked":
      return `${PROVIDER_LABEL[d.provider as Provider] ?? "Another sign-in"}${typeof d.email === "string" ? ` (${d.email})` : ""} linked to your account`;
    case "account.identity_unlinked":
      return `${PROVIDER_LABEL[d.provider as Provider] ?? "Another sign-in"}${typeof d.email === "string" ? ` (${d.email})` : ""} unlinked from your account`;
    case "password.changed":
      return "Password changed";
    case "password.set":
      return "Password added";
    case "password.removed":
      return "Password removed";
    case "password.reset":
      return "Password reset from an emailed link";
    case "mfa.totp_enabled":
      return "Authenticator app turned on";
    case "mfa.totp_disabled":
      return "Authenticator app turned off";
    case "mfa.recovery_code_used":
      return typeof d.remaining === "number" ? `Recovery code used (${d.remaining} left)` : "Recovery code used";
    case "recovery.started":
      return "Asked to remove your second steps because they were lost";
    case "recovery.cancelled":
      return "Request to remove your second steps cancelled";
    case "recovery.completed":
      return "Your second steps were removed after a lost-device request";
    case "mfa.requirement_changed":
      return d.required ? "Turned on: always ask for a second step" : "Turned off: always ask for a second step";
    case "mfa.recovery_codes_replaced":
      return "New recovery codes made; the old ones stopped working";
    case "passkey.added":
    case "passkey.removed": {
      const what = d.kind === "security_key" ? "Security key" : "Passkey";
      const done = action === "passkey.added" ? "added" : "removed";
      return typeof d.name === "string" ? `${what} "${d.name}" ${done}` : `${what} ${done}`;
    }
    case "passkey.renamed":
      return typeof d.name === "string" && typeof d.from === "string" ? `Renamed "${d.from}" to "${d.name}"` : "Renamed a passkey";
    case "oauth.access_removed":
      return "Removed an app's access to the account";
    case "oauth.consent_granted":
      return "Allowed an app to use your account";
    case "oauth.refresh_reuse_detected":
      return "An app's sign-in was used twice, so it was signed out to be safe";
    default:
      return action;
  }
}

/** Events worth a second look even when nothing else is odd. */
const ALWAYS_NOTABLE = new Set<string>(["auth.sign_in_failed", "oauth.refresh_reuse_detected", "mfa.recovery_code_used", "mfa.totp_disabled", "password.removed", "passkey.removed", "password.reset", "account.identity_linked", "account.identity_unlinked", "email.primary_changed", "email.change_undone", "account.merge_requested", "account.merge_confirmed", "account.merged", "account.session_policy_changed", "recovery.started", "recovery.cancelled", "recovery.completed", "password.breach_detected", "auth.unusual_sign_in", "account.contained", "account.unlocked", "account.locked", "account.frozen", "account.unfreeze_scheduled", "account.unfreeze_cancelled"]);

export function isNotable(action: string, newDevice: boolean) {
  return newDevice || ALWAYS_NOTABLE.has(action);
}

/** "Chrome on Windows", "Safari on iPhone", "Mobile app" — enough to recognise a device, no more. */
export function deviceLabel(userAgent: string | null | undefined): string {
  const ua = userAgent ?? "";
  if (!ua.trim()) return "Unknown device";
  if (/okhttp|CFNetwork|Expo|Dalvik|NoirlyFlow|NoirlyLedger|NoirlySplit|NoirlyPulse/i.test(ua) && !/Mozilla\//.test(ua)) return "Mobile app";
  const browser =
    /Edg(e|A|iOS)?\//.test(ua) ? "Edge"
    : /OPR\/|Opera/.test(ua) ? "Opera"
    : /SamsungBrowser\//.test(ua) ? "Samsung Internet"
    : /Firefox\/|FxiOS\//.test(ua) ? "Firefox"
    : /Chrome\/|CriOS\//.test(ua) ? "Chrome"
    : /Safari\//.test(ua) && /Version\//.test(ua) ? "Safari"
    : null;
  const os =
    /iPhone/.test(ua) ? "iPhone"
    : /iPad/.test(ua) ? "iPad"
    : /Android/.test(ua) ? "Android"
    : /CrOS/.test(ua) ? "ChromeOS"
    : /Windows/.test(ua) ? "Windows"
    : /Mac OS X|Macintosh/.test(ua) ? "Mac"
    : /Linux/.test(ua) ? "Linux"
    : null;
  if (browser && os) return `${browser} on ${os}`;
  return browser ?? os ?? "Unknown device";
}

/**
 * Which sign-ins came from a device the account hadn't signed in from
 * before. `signIns` is every successful sign-in, oldest first; the very
 * first sign-in an account makes isn't flagged (every device is new then).
 */
export function newDeviceSignIns(signIns: Array<{ seq: number; device: string }>): Set<number> {
  const seen = new Set<string>();
  const flagged = new Set<number>();
  for (const signIn of signIns) {
    if (seen.size > 0 && !seen.has(signIn.device)) flagged.add(signIn.seq);
    seen.add(signIn.device);
  }
  return flagged;
}

export type ActivityItem = {
  seq: number;
  at: string;
  kind: ActivityKind;
  action: string;
  title: string;
  device: string;
  ipAddress: string | null;
  app: string | null;
  newDevice: boolean;
  notable: boolean;
};
