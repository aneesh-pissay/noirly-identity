/**
 * What each scope lets an app see, in words for the person whose account it
 * is. Shared by the server and the account page, so it holds no server code.
 */

export const SCOPE_MEANING: Record<string, string> = {
  openid: "That it's you, by your Noirly account ID",
  profile: "Your name, photo, language, time zone and accessibility settings",
  email: "Your primary email address and whether it's confirmed",
  offline_access: "Stay signed in to you while you're away",
  roles: "Your Noirly Identity roles",
  organizations: "The spaces you belong to",
  permissions: "What you're allowed to do in the organization you open it in",
};

/** The scopes an app holds, as sentences, in a steady order; unknown ones by name. */
export function describeScopes(scopes: string[]): string[] {
  const order = Object.keys(SCOPE_MEANING);
  return [...new Set(scopes)]
    .sort((a, b) => (order.indexOf(a) === -1 ? 99 : order.indexOf(a)) - (order.indexOf(b) === -1 ? 99 : order.indexOf(b)))
    .map((scope) => SCOPE_MEANING[scope] ?? scope);
}

export type AppAccessView = {
  clientId: string;
  name: string;
  kind: "web" | "mobile";
  canSee: string[];
  /** Each granted scope in words, and when it was first granted. */
  grants: Array<{ scope: string; text: string; since: string }>;
  scopes: string[];
  firstUsedAt: string;
  lastUsedAt: string;
  /** Holds a token that still works right now. */
  signedIn: boolean;
};
