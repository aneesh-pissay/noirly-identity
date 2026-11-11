export function redactSecretInUrl(url: string): string {
  try {
    const parsed = new URL(url);
    if (parsed.searchParams.has("token")) {
      parsed.searchParams.set("token", "[REDACTED]");
    }
    return parsed.toString();
  } catch {
    return url.replace(/([?&]token=)[^&]+/gi, "$1[REDACTED]");
  }
}

export function maskEmail(email: string): string {
  const normalized = email.trim().toLowerCase();
  const at = normalized.indexOf("@");
  if (at <= 0) {
    return "***";
  }
  const local = normalized.slice(0, at);
  const domain = normalized.slice(at + 1);
  const visible = local.slice(0, 1);
  return `${visible}***@${domain}`;
}

export function buildVerificationEmail(input: {
  name: string;
  verifyUrl: string;
  expiresInHours: number;
  /** For typing in where the link is awkward (an app, another device). */
  code?: string;
}): { subject: string; text: string; html: string } {
  const subject = "Verify your Noirly account";
  const text = [
    `Hi ${input.name},`,
    "",
    "Thanks for creating your Noirly account.",
    "",
    "Please verify your email address to continue using Noirly.",
    "",
    `Verify my email: ${input.verifyUrl}`,
    ...(input.code ? ["", `Or enter this code: ${input.code}`] : []),
    "",
    `This verification ${input.code ? "link and code" : "link"} will expire in ${input.expiresInHours} hours.`,
    "",
    "If you didn't create a Noirly account, you can safely ignore this email.",
    "",
    "Thanks,",
    "The Noirly Team",
  ].join("\n");

  const html = `
    <div style="font-family: Arial, sans-serif; line-height: 1.5; color: #18181b;">
      <p>Hi ${escapeHtml(input.name)},</p>
      <p>Thanks for creating your Noirly account.</p>
      <p>Please verify your email address to continue using Noirly.</p>
      <p style="margin: 24px 0;">
        <a href="${escapeHtml(input.verifyUrl)}"
           style="background:#18181b;color:#fff;padding:12px 18px;text-decoration:none;border-radius:6px;display:inline-block;">
          Verify my email
        </a>
      </p>
      ${input.code ? `<p>Or enter this code:</p><p style="font-size: 28px; font-weight: 700; letter-spacing: 4px; font-family: monospace;">${escapeHtml(input.code)}</p>` : ""}
      <p>This verification ${input.code ? "link and code" : "link"} will expire in ${input.expiresInHours} hours.</p>
      <p>If you didn't create a Noirly account, you can safely ignore this email.</p>
      <p>Thanks,<br/>The Noirly Team</p>
    </div>
  `.trim();

  return { subject, text, html };
}

/** A sign-in link, which only works in the browser that asked for it. */
export function buildMagicLinkEmail(input: {
  signInUrl: string;
  code: string;
  expiresInMinutes: number;
  device: string;
}): { subject: string; text: string; html: string } {
  const subject = `Your Noirly sign-in code: ${input.code}`;
  const text = [
    "Hi,",
    "",
    `Here's the link to sign in to Noirly, asked for from ${input.device}:`,
    input.signInUrl,
    "",
    `Or type this code where you asked: ${input.code}`,
    "",
    `Either works once, for ${input.expiresInMinutes} minutes, and only in the browser where you asked for it.`,
    "",
    "If you didn't ask to sign in, ignore this email: nobody can use the link without that browser.",
    "",
    "Thanks,",
    "The Noirly Team",
  ].join("\n");

  const html = `
    <div style="font-family: Arial, sans-serif; line-height: 1.5; color: #18181b;">
      <p>Hi,</p>
      <p>Here's the link to sign in to Noirly, asked for from ${escapeHtml(input.device)}.</p>
      <p style="margin: 24px 0;">
        <a href="${escapeHtml(input.signInUrl)}"
           style="background:#18181b;color:#fff;padding:12px 18px;text-decoration:none;border-radius:6px;display:inline-block;">
          Sign in to Noirly
        </a>
      </p>
      <p>Or type this code where you asked:</p>
      <p style="font-size: 28px; font-weight: 700; letter-spacing: 4px; font-family: monospace;">${escapeHtml(input.code)}</p>
      <p>Either works once, for ${input.expiresInMinutes} minutes, and only in the browser where you asked for it.</p>
      <p>If you didn't ask to sign in, ignore this email: nobody can use the link without that browser.</p>
      <p>Thanks,<br/>The Noirly Team</p>
    </div>
  `.trim();

  return { subject, text, html };
}

/** After a sign-in uses up most of the recovery codes. */
export function buildRecoveryCodesLowEmail(input: { remaining: number; accountUrl: string }): { subject: string; text: string; html: string } {
  const left = input.remaining === 0 ? "no recovery codes left" : `only ${input.remaining} recovery code${input.remaining === 1 ? "" : "s"} left`;
  const subject = "Your Noirly recovery codes are running out";
  const text = [
    "Hi,",
    "",
    `A recovery code was just used to sign in to your Noirly account, and you have ${left}.`,
    "",
    `Make a new set from your account page; the old codes stop working when you do: ${input.accountUrl}`,
    "",
    "If you didn't just sign in, change your password and check your account's security activity.",
    "",
    "Thanks,",
    "The Noirly Team",
  ].join("\n");
  const html = `
    <div style="font-family: Arial, sans-serif; line-height: 1.5; color: #18181b;">
      <p>Hi,</p>
      <p>A recovery code was just used to sign in to your Noirly account, and you have ${escapeHtml(left)}.</p>
      <p>Make a new set from your account page; the old codes stop working when you do.</p>
      <p style="margin: 24px 0;">
        <a href="${escapeHtml(input.accountUrl)}" style="background:#18181b;color:#fff;padding:12px 18px;text-decoration:none;border-radius:6px;display:inline-block;">Make new recovery codes</a>
      </p>
      <p>If you didn't just sign in, change your password and check your account's security activity.</p>
      <p>Thanks,<br/>The Noirly Team</p>
    </div>
  `.trim();
  return { subject, text, html };
}

/** Someone asked to remove the account's second steps: to every verified address, with a way to stop it. */
export function buildRecoveryStartedEmail(input: { availableAt: string; cancelUrl: string }): { subject: string; text: string; html: string } {
  const subject = "Someone asked to remove your Noirly second sign-in step";
  const text = [
    "Hi,",
    "",
    "Someone signed in to your Noirly account with its first step and said they've lost their authenticator app, passkey or security key.",
    "",
    `If nobody stops it, they can remove your second steps after ${input.availableAt}, and sign in without one.`,
    "",
    `If this wasn't you, cancel it now, then change your password: ${input.cancelUrl}`,
    "",
    "If it was you, there's nothing to do: come back after that time to finish.",
    "",
    "Thanks,",
    "The Noirly Team",
  ].join("\n");
  const html = `
    <div style="font-family: Arial, sans-serif; line-height: 1.5; color: #18181b;">
      <p>Hi,</p>
      <p>Someone signed in to your Noirly account with its first step and said they've lost their authenticator app, passkey or security key.</p>
      <p>If nobody stops it, they can remove your second steps after <strong>${escapeHtml(input.availableAt)}</strong>, and sign in without one.</p>
      <p>If this wasn't you, cancel it now, then change your password:</p>
      <p style="margin: 24px 0;">
        <a href="${escapeHtml(input.cancelUrl)}" style="background:#18181b;color:#fff;padding:12px 18px;text-decoration:none;border-radius:6px;display:inline-block;">This wasn't me, cancel it</a>
      </p>
      <p>If it was you, there's nothing to do: come back after that time to finish.</p>
      <p>Thanks,<br/>The Noirly Team</p>
    </div>
  `.trim();
  return { subject, text, html };
}

/** The second steps are gone: so the owner knows, wherever they read email. */
export function buildRecoveryCompletedEmail(): { subject: string; text: string; html: string } {
  const subject = "Your Noirly second sign-in steps were removed";
  const text = [
    "Hi,",
    "",
    "After the waiting period, your authenticator app, passkeys and security keys were removed from your Noirly account, and every other device was signed out.",
    "",
    "Set up a new second step from your account page as soon as you can.",
    "",
    "If you didn't ask for this, reset your password straight away and check your account's security activity.",
    "",
    "Thanks,",
    "The Noirly Team",
  ].join("\n");
  const html = `
    <div style="font-family: Arial, sans-serif; line-height: 1.5; color: #18181b;">
      <p>Hi,</p>
      <p>After the waiting period, your authenticator app, passkeys and security keys were removed from your Noirly account, and every other device was signed out.</p>
      <p>Set up a new second step from your account page as soon as you can.</p>
      <p>If you didn't ask for this, reset your password straight away and check your account's security activity.</p>
      <p>Thanks,<br/>The Noirly Team</p>
    </div>
  `.trim();
  return { subject, text, html };
}

/** A space now requires a second step, and the account has none yet. */
export function buildMfaEnrollmentEmail(input: { spaces: string[]; days: number; until: string; accountUrl: string }): { subject: string; text: string; html: string } {
  const which = input.spaces.length === 1 ? `The ${input.spaces[0]} space` : `Your spaces (${input.spaces.join(", ")})`;
  const subject = "Set up a second sign-in step for Noirly";
  const text = [
    "Hi,",
    "",
    `${which} now asks every member to use a second step when signing in: an authenticator app, a passkey or a security key.`,
    "",
    `Set one up within ${input.days} days (by ${input.until}). After that, Noirly apps won't let you in until you do.`,
    "",
    `Set one up: ${input.accountUrl}`,
    "",
    "Thanks,",
    "The Noirly Team",
  ].join("\n");
  const html = `
    <div style="font-family: Arial, sans-serif; line-height: 1.5; color: #18181b;">
      <p>Hi,</p>
      <p>${escapeHtml(which)} now asks every member to use a second step when signing in: an authenticator app, a passkey or a security key.</p>
      <p>Set one up within ${input.days} days (by ${escapeHtml(input.until)}). After that, Noirly apps won't let you in until you do.</p>
      <p style="margin: 24px 0;">
        <a href="${escapeHtml(input.accountUrl)}" style="background:#18181b;color:#fff;padding:12px 18px;text-decoration:none;border-radius:6px;display:inline-block;">Set up a second step</a>
      </p>
      <p>Thanks,<br/>The Noirly Team</p>
    </div>
  `.trim();
  return { subject, text, html };
}

/** To an address someone wants to add to their account. */
export function buildAddressVerificationEmail(input: {
  accountEmail: string;
  verifyUrl: string;
  expiresInHours: number;
}): { subject: string; text: string; html: string } {
  const subject = "Confirm this email address for Noirly";
  const text = [
    "Hi,",
    "",
    `Someone signed in as ${input.accountEmail} asked to add this address to their Noirly account.`,
    "",
    `If that was you, confirm it: ${input.verifyUrl}`,
    "",
    `This link will expire in ${input.expiresInHours} hours.`,
    "",
    "If it wasn't you, ignore this email: the address won't be added.",
    "",
    "Thanks,",
    "The Noirly Team",
  ].join("\n");

  const html = `
    <div style="font-family: Arial, sans-serif; line-height: 1.5; color: #18181b;">
      <p>Hi,</p>
      <p>Someone signed in as ${escapeHtml(input.accountEmail)} asked to add this address to their Noirly account.</p>
      <p style="margin: 24px 0;">
        <a href="${escapeHtml(input.verifyUrl)}"
           style="background:#18181b;color:#fff;padding:12px 18px;text-decoration:none;border-radius:6px;display:inline-block;">
          Confirm this address
        </a>
      </p>
      <p>This link will expire in ${input.expiresInHours} hours.</p>
      <p>If it wasn't you, ignore this email: the address won't be added.</p>
      <p>Thanks,<br/>The Noirly Team</p>
    </div>
  `.trim();

  return { subject, text, html };
}

/** To the account that would be merged away: only its owner can say yes. */
export function buildMergeConfirmEmail(input: {
  keeperEmail: string;
  confirmUrl: string;
  expiresInHours: number;
}): { subject: string; text: string; html: string } {
  const subject = "Merge your Noirly accounts?";
  const text = [
    "Hi,",
    "",
    `Someone signed in as ${input.keeperEmail} asked to merge this Noirly account into theirs.`,
    "",
    "If that's you, confirm it here. Nothing changes until you've reviewed the merge from that account and completed it:",
    input.confirmUrl,
    "",
    `This link will expire in ${input.expiresInHours} hours.`,
    "",
    "If it wasn't you, ignore this email: without it, nothing can be merged.",
    "",
    "Thanks,",
    "The Noirly Team",
  ].join("\n");

  const html = `
    <div style="font-family: Arial, sans-serif; line-height: 1.5; color: #18181b;">
      <p>Hi,</p>
      <p>Someone signed in as ${escapeHtml(input.keeperEmail)} asked to merge this Noirly account into theirs.</p>
      <p>If that's you, confirm it. Nothing changes until you've reviewed the merge from that account and completed it.</p>
      <p style="margin: 24px 0;">
        <a href="${escapeHtml(input.confirmUrl)}"
           style="background:#18181b;color:#fff;padding:12px 18px;text-decoration:none;border-radius:6px;display:inline-block;">
          Confirm it's me
        </a>
      </p>
      <p>This link will expire in ${input.expiresInHours} hours.</p>
      <p>If it wasn't you, ignore this email: without it, nothing can be merged.</p>
      <p>Thanks,<br/>The Noirly Team</p>
    </div>
  `.trim();

  return { subject, text, html };
}

/** To the old primary address, once another address takes its place. */
export function buildPrimaryChangedEmail(input: {
  newEmail: string;
  undoUrl: string;
  undoDays: number;
}): { subject: string; text: string; html: string } {
  const subject = "Your Noirly primary email address changed";
  const text = [
    "Hi,",
    "",
    `Your Noirly account's primary email address is now ${input.newEmail}. Sign-in links and security notices go there from now on.`,
    "",
    "This address stays on your account as an additional one.",
    "",
    `If you didn't make this change, undo it: ${input.undoUrl}`,
    "",
    `Undoing puts this address back as primary, removes the new one, and signs out everywhere. The link works for ${input.undoDays} days.`,
    "",
    "Thanks,",
    "The Noirly Team",
  ].join("\n");

  const html = `
    <div style="font-family: Arial, sans-serif; line-height: 1.5; color: #18181b;">
      <p>Hi,</p>
      <p>Your Noirly account's primary email address is now <strong>${escapeHtml(input.newEmail)}</strong>. Sign-in links and security notices go there from now on.</p>
      <p>This address stays on your account as an additional one.</p>
      <p>If you didn't make this change, undo it:</p>
      <p style="margin: 24px 0;">
        <a href="${escapeHtml(input.undoUrl)}"
           style="background:#18181b;color:#fff;padding:12px 18px;text-decoration:none;border-radius:6px;display:inline-block;">
          This wasn't me
        </a>
      </p>
      <p>Undoing puts this address back as primary, removes the new one, and signs out everywhere. The link works for ${input.undoDays} days.</p>
      <p>Thanks,<br/>The Noirly Team</p>
    </div>
  `.trim();

  return { subject, text, html };
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/**
 * A plain notice: a few paragraphs and, optionally, one button. Shared by the
 * simpler messages (invitations, alerts, lifecycle notices) so each reads the
 * same and escapes the same.
 */
export function buildNoticeEmail(input: {
  subject: string;
  paragraphs: string[];
  action?: { label: string; url: string };
  footer?: string[];
}): { subject: string; text: string; html: string } {
  const text = [
    "Hi,",
    "",
    ...input.paragraphs.flatMap((p) => [p, ""]),
    ...(input.action ? [`${input.action.label}: ${input.action.url}`, ""] : []),
    ...(input.footer ?? []).flatMap((p) => [p, ""]),
    "Thanks,",
    "The Noirly Team",
  ].join("\n");
  const button = input.action
    ? `<p style="margin: 24px 0;"><a href="${escapeHtml(input.action.url)}" style="background:#18181b;color:#fff;padding:12px 18px;text-decoration:none;border-radius:6px;display:inline-block;">${escapeHtml(input.action.label)}</a></p>`
    : "";
  const html = `
    <div style="font-family: Arial, sans-serif; line-height: 1.5; color: #18181b;">
      <p>Hi,</p>
      ${input.paragraphs.map((p) => `<p>${escapeHtml(p)}</p>`).join("\n      ")}
      ${button}
      ${(input.footer ?? []).map((p) => `<p>${escapeHtml(p)}</p>`).join("\n      ")}
      <p>Thanks,<br/>The Noirly Team</p>
    </div>
  `.trim();
  return { subject: input.subject, text, html };
}
