import Link from "next/link";
import { redirect } from "next/navigation";
import { AccountPageHeader, AccountSections } from "@/components/account/AccountPageHeader";
import { MobileSignOut } from "@/components/account/AccountNav";
import { FreezeAccount } from "@/components/security/FreezeAccount";
import { MergeAccounts } from "@/components/security/MergeAccounts";
import { withDb } from "@/lib/api/with-db";
import { getRequestUser } from "@/lib/auth/request-user";
import { ownsAnyApp } from "@/lib/oauth/app-owners";

export const metadata = { title: "Account · Noirly Identity" };

const ADMIN_TOOLS = [
  { href: "/clients", label: "Apps", why: "Register and manage the apps that sign people in." },
  { href: "/apis", label: "APIs", why: "APIs that accept Identity tokens, and who may call them." },
  { href: "/admin/security", label: "Account protection", why: "Lock a possibly taken-over account; review risky recoveries." },
  { href: "/admin/audit", label: "Audit log", why: "Search, export and get alerts on every sign-in and change." },
  { href: "/admin/deletions", label: "Account deletions", why: "Which apps confirmed each deletion." },
  { href: "/admin/claims", label: "Claim review", why: "Trim what apps may ask for to what they use." },
];

/** Spaces, admin tools, merging, freezing and closing. */
export default async function ManageAccountPage() {
  const user = await getRequestUser();
  if (!user) redirect("/login?return_to=/account/manage");
  const isAdmin = user.roles.includes("admin");
  const ownsApps = !isAdmin && (await withDb(() => ownsAnyApp(user.id)));
  const card = "rounded-2xl border border-[var(--hairline)] p-6";
  return (
    <>
      <AccountPageHeader title="Account" lead="Your spaces, tools, and the bigger changes: merging two accounts, freezing, or closing your account." />
      <AccountSections>
        <section aria-labelledby="spaces-title" className={`${card} space-y-2`}>
          <h2 id="spaces-title" className="text-xl font-semibold">Spaces</h2>
          <p className="text-sm text-[var(--muted-foreground)]">Teams you belong to across every Noirly app: a household, a club or a company.</p>
          <Link href="/spaces" className="inline-block text-sm underline">Open your spaces</Link>
        </section>

        {isAdmin || ownsApps ? (
          <section aria-labelledby="tools-title" className={`${card} space-y-3`}>
            <h2 id="tools-title" className="text-xl font-semibold">{isAdmin ? "Admin tools" : "Your apps"}</h2>
            <ul className="grid gap-3 sm:grid-cols-2">
              {(isAdmin ? ADMIN_TOOLS : ADMIN_TOOLS.slice(0, 1)).map((tool) => (
                <li key={tool.href}>
                  <Link href={tool.href} className="block h-full rounded-xl border border-[var(--hairline)] p-4 hover:border-[var(--accent)]">
                    <span className="block font-medium">{tool.label}</span>
                    <span className="mt-1 block text-sm text-[var(--muted-foreground)]">{tool.why}</span>
                  </Link>
                </li>
              ))}
            </ul>
          </section>
        ) : null}

        <MergeAccounts />
        <FreezeAccount />

        <section aria-labelledby="close-title" className={`${card} space-y-2`}>
          <h2 id="close-title" className="text-xl font-semibold">Close your account</h2>
          <p className="text-sm text-[var(--muted-foreground)]">
            Your account is locked at once and deleted after 14 days, with your data in every Noirly app. Until then, the email we send you can undo it.
            Get a copy of your data first on <Link href="/account/privacy" className="underline">Privacy and apps</Link>.
          </p>
          <Link href="/delete-account" className="inline-block text-sm text-red-400 underline hover:text-red-300">Close my account</Link>
        </section>

        <div className="flex flex-wrap items-center gap-4 text-sm md:hidden">
          <MobileSignOut />
          <Link href="/docs" className="underline">Help and docs</Link>
        </div>
      </AccountSections>
    </>
  );
}
