import { getEnv } from "@/lib/config/env";
import { sendEmail } from "@/lib/email/email-service";
import { buildNoticeEmail } from "@/lib/email/templates";
import { User } from "@/models/User";
import { freezeLink } from "@/lib/security/account-lock";

/**
 * Security alerts by email, for the events someone should hear about at once
 * if it wasn't them. Sent from the event log (lib/audit/event-log.ts), so
 * every way of doing these things alerts the same. Messages that already
 * email someone (a primary address change, recovery) aren't repeated here.
 */

const SIGNALS: Record<string, string> = {
  new_device: "a device we haven't seen you use",
  new_country: "a country we haven't seen you sign in from",
  impossible_travel: "a different country only shortly after your last sign-in",
};

const ALERTS: Record<string, (data: Record<string, unknown>) => { subject: string; line: string } | null> = {
  "auth.unusual_sign_in": (d) => ({
    subject: "New sign-in to your Noirly account",
    line: `Your account was just signed in to from ${((d.signals as string[] | undefined) ?? []).map((s) => SIGNALS[s] ?? s).join(", and ") || "somewhere new"}.`,
  }),
  "mfa.totp_enabled": () => ({ subject: "Authenticator app added", line: "An authenticator app was added to your account as a second step." }),
  "mfa.totp_disabled": () => ({ subject: "Authenticator app removed", line: "The authenticator app was removed from your account." }),
  "passkey.added": () => ({ subject: "Passkey added", line: "A passkey or security key was added to your account." }),
  "passkey.removed": () => ({ subject: "Passkey removed", line: "A passkey or security key was removed from your account." }),
  "password.changed": () => ({ subject: "Password changed", line: "Your password was changed." }),
  "password.reset": () => ({ subject: "Password reset", line: "Your password was reset with an emailed link." }),
  "password.set": () => ({ subject: "Password added", line: "A password was added to your account." }),
  "password.removed": () => ({ subject: "Password removed", line: "The password was removed from your account." }),
  "email.added": (d) => ({ subject: "Email address added", line: `${typeof d.email === "string" ? d.email : "An address"} was added to your account.` }),
  "email.removed": (d) => ({ subject: "Email address removed", line: `${typeof d.email === "string" ? d.email : "An address"} was removed from your account.` }),
  "recovery_method.added": () => ({ subject: "Recovery address added", line: "A recovery address was added to your account." }),
  "recovery_method.removed": () => ({ subject: "Recovery address removed", line: "Your account's recovery address was removed." }),
  "account.identity_linked": (d) => ({ subject: "Sign-in method linked", line: `${typeof d.provider === "string" ? d.provider : "A provider"} can now sign in to your account.` }),
};

export function alertsFor(action: string) {
  return action in ALERTS;
}

export async function sendSecurityAlert(action: string, userId: string, data: Record<string, unknown>) {
  const build = ALERTS[action];
  if (!build) return;
  const message = build(data);
  if (!message) return;
  const user = await User.findById(userId).select("email emailVerified status").lean();
  if (!user || !user.emailVerified || user.status !== "active") return;
  const freeze = await freezeLink(user._id);
  await sendEmail({
    to: user.email,
    ...buildNoticeEmail({
      subject: message.subject,
      paragraphs: [message.line, "If this was you, there's nothing to do. If it wasn't, change your password and sign out everywhere from your account page now."],
      action: { label: "Review your account", url: new URL("/account", getEnv().APP_URL).toString() },
      footer: [`Not you and can't get in? Freeze your account at once: ${freeze}`],
    }),
    meta: { kind: `alert:${action}` },
  });
}
