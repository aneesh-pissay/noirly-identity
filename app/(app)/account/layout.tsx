import type { ReactNode } from "react";
import { AccountNav } from "@/components/account/AccountNav";
import { withDb } from "@/lib/api/with-db";
import { getRequestUser } from "@/lib/auth/request-user";
import { ownsAnyApp } from "@/lib/oauth/app-owners";

/**
 * The account area: a sidebar of six areas (Home, Personal info, Security,
 * Devices, Privacy and apps, Account) beside one short page at a time.
 * Signed out, each page sends people to sign in, back to that page.
 */
export default async function AccountLayout({ children }: { children: ReactNode }) {
  const user = await getRequestUser();
  if (!user) return children;
  const isAdmin = user.roles.includes("admin");
  const ownsApps = isAdmin || (await withDb(() => ownsAnyApp(user.id)));
  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col px-4 pb-16 pt-16 sm:px-6 md:flex-row md:gap-10 md:pt-10">
      <AccountNav user={{ displayName: user.displayName, email: user.email, avatarUrl: user.avatarUrl }} isAdmin={isAdmin} ownsApps={ownsApps} />
      <main id="main" className="min-w-0 flex-1">{children}</main>
    </div>
  );
}
