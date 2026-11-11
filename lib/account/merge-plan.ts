/**
 * Merging two accounts that belong to one person: the account they keep
 * takes in the other's ways to sign in, email addresses, spaces and app
 * history; the other account is then closed, and apps are told its `sub`
 * now belongs to the kept one. Where both have something only one can keep
 * (an authenticator app, a Google link, a password, a photo, the profile),
 * the kept account's wins and the other's is dropped. Shared by the server
 * and the account page, so it holds no server code.
 */

export type MergeSide = {
  email: string;
  password: boolean;
  totp: boolean;
  passkeys: number;
  providers: Array<{ provider: string; email: string | null }>;
  verifiedEmails: string[];
  photo: boolean;
  admin: boolean;
  spaces: Array<{ id: string; name: string; role: "owner" | "admin" | "member" }>;
  apps: number;
};

export type MergePlan = { moves: string[]; drops: string[] };

const RANK = { member: 1, admin: 2, owner: 3 } as const;

function plural(n: number, one: string, many = `${one}s`) {
  return `${n} ${n === 1 ? one : many}`;
}

/** What happens to the other account's things, in words, before anything changes. */
export function mergePlan(keep: MergeSide, other: MergeSide): MergePlan {
  const moves: string[] = [];
  const drops: string[] = [];

  const emails = [other.email, ...other.verifiedEmails].filter((e) => e !== keep.email && !keep.verifiedEmails.includes(e));
  if (emails.length) moves.push(`Email ${emails.length === 1 ? "address" : "addresses"} ${emails.join(", ")}, as confirmed additional ${emails.length === 1 ? "address" : "addresses"}`);

  if (other.password) {
    if (keep.password) drops.push("The other account's password (you keep this one's)");
    else moves.push("Its password, which then signs in to this account");
  }
  if (other.totp) {
    if (keep.totp) drops.push("The other account's authenticator app and recovery codes (you keep this one's)");
    else moves.push("Its authenticator app and recovery codes");
  }
  if (other.passkeys) moves.push(plural(other.passkeys, "passkey"));
  for (const link of other.providers) {
    const label = `${link.provider === "google" ? "Google" : link.provider}${link.email ? ` (${link.email})` : ""}`;
    if (keep.providers.some((p) => p.provider === link.provider)) drops.push(`Its ${label} link (this account already has one)`);
    else moves.push(`Its ${label} link`);
  }

  for (const space of other.spaces) {
    const mine = keep.spaces.find((s) => s.id === space.id);
    if (!mine) moves.push(`Membership of ${space.name} (${space.role})`);
    else if (RANK[space.role] > RANK[mine.role]) moves.push(`Your ${space.role} role in ${space.name}, which you're already in as ${mine.role}`);
  }
  if (other.apps) moves.push(`The record of ${plural(other.apps, "app")} it signed in to`);

  if (other.photo && !keep.photo) moves.push("Its profile photo");
  else if (other.photo) drops.push("The other account's photo (you keep this one's)");
  drops.push("The other account's name and preferences (you keep this one's)");
  if (other.admin && !keep.admin) drops.push("The other account's Identity admin role");
  drops.push("Its sign-ins: it's signed out everywhere and closed");
  return { moves, drops };
}

export type MergeRequestView = {
  id: string;
  status: "awaiting_confirmation" | "confirmed";
  otherEmail: string;
  expiresAt: string;
  plan: MergePlan | null;
};
