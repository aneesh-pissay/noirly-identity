import { AppError } from "@/lib/api/errors";

/**
 * Apps trust the email Identity vouches for (most treat it as the person's
 * address), so nothing leaves Identity for an account whose email was never
 * proven: anyone can register any address.
 */
export function assertEmailVerified(user: { emailVerified?: boolean | null; status: string }): void {
  if (!user.emailVerified || user.status === "pending_verification") {
    throw new AppError(
      "Please verify your email address before signing in.",
      403,
      "email_not_verified",
    );
  }
}

/** Development seed identities must never authenticate in a deployed production app. */
export function isBlockedUser(user: { email: string; status: string }): boolean {
  return user.status === "disabled" ||
    (process.env.NODE_ENV === "production" && user.email === "dev@noirly.test");
}
