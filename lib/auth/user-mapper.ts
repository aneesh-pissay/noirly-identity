import type { UserDocument } from "@/models/User";
import type { PublicUser } from "@/types";
import { accessibilityOf } from "@/lib/account/preferences";

/** Hydrated or lean user docs both work — only needs public fields + optional hash. */
type UserLike = Pick<
  UserDocument,
  | "email"
  | "emailVerified"
  | "firstName"
  | "lastName"
  | "displayName"
  | "avatarUrl"
  | "phoneNumber"
  | "phoneVerifiedAt"
  | "locale"
  | "zoneinfo"
  | "accessibility"
  | "status"
  | "roles"
  | "createdAt"
  | "updatedAt"
  | "lastLoginAt"
> & {
  _id: UserDocument["_id"] | string;
  passwordHash?: string | null;
};

export function toPublicUser(user: UserLike): PublicUser {
  return {
    id: String(user._id),
    email: user.email,
    emailVerified: user.emailVerified,
    firstName: user.firstName,
    lastName: user.lastName,
    displayName: user.displayName,
    avatarUrl: user.avatarUrl ?? null,
    phoneNumber: user.phoneNumber ?? null,
    phoneVerified: Boolean(user.phoneNumber && user.phoneVerifiedAt),
    locale: user.locale ?? null,
    zoneinfo: user.zoneinfo ?? null,
    accessibility: accessibilityOf(user.accessibility),
    hasPassword: Boolean(user.passwordHash),
    passwordBreached: Boolean(user.passwordHash && (user as { passwordBreachedAt?: Date | null }).passwordBreachedAt),
    status: user.status,
    roles: user.roles as PublicUser["roles"],
    createdAt: user.createdAt.toISOString(),
    updatedAt: user.updatedAt.toISOString(),
    lastLoginAt: user.lastLoginAt ? user.lastLoginAt.toISOString() : null,
  };
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}
