import { redirect } from "next/navigation";
import { AccountPageHeader, AccountSections } from "@/components/account/AccountPageHeader";
import { ConnectedApps } from "@/components/security/ConnectedApps";
import { DataExports } from "@/components/security/DataExports";
import { withDb } from "@/lib/api/with-db";
import { privacySummary } from "@/lib/account/privacy";
import { getRequestUser } from "@/lib/auth/request-user";

export const metadata = { title: "Privacy and apps · Noirly Identity" };

/** The apps you've let in, what Identity holds about you and why, and getting all of it. */
export default async function PrivacyPage() {
  const user = await getRequestUser();
  if (!user) redirect("/login?return_to=/account/privacy");
  const categories = await withDb(() => privacySummary(user.id));
  return (
    <>
      <AccountPageHeader title="Privacy and apps" lead="Which apps can see your details, what Noirly Identity keeps about you and why, and a copy of all of it." />
      <AccountSections>
        <ConnectedApps />
        <section aria-labelledby="holds-title" className="space-y-4 rounded-2xl border border-[var(--hairline)] p-6">
          <div>
            <h2 id="holds-title" className="text-xl font-semibold">What Identity keeps</h2>
            <p className="mt-1 text-sm text-[var(--muted-foreground)]">What Noirly Identity holds about you, why, and for how long. Apps keep their own data.</p>
          </div>
          <ul aria-label="What Identity holds" className="divide-y divide-[var(--hairline)]">
            {categories.map((c) => (
              <li key={c.id} className="grid gap-1 py-3 sm:grid-cols-[12rem_minmax(0,1fr)] sm:gap-4">
                <p className="font-medium">
                  {c.label} <span className="text-xs font-normal text-[var(--muted-foreground)]">{c.count === 0 ? "none" : c.count}</span>
                </p>
                <div>
                  <p className="text-sm text-[var(--muted-foreground)]">{c.why}</p>
                  <p className="text-xs text-[var(--muted-foreground)]">Kept: {c.kept}</p>
                </div>
              </li>
            ))}
          </ul>
          <a className="inline-block text-sm underline" href="/api/auth/export" download>Download what Identity keeps</a>
        </section>
        <DataExports />
      </AccountSections>
    </>
  );
}
