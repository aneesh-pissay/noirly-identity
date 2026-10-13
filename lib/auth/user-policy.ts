/** Development seed identities must never authenticate in a deployed production app. */
export function isBlockedUser(user: { email: string; status: string }): boolean {
  return user.status === "disabled" ||
    (process.env.NODE_ENV === "production" && user.email === "dev@noirly.test");
}
