import { redirect } from "next/navigation";
import { ConnectedApps } from "@/components/security/ConnectedApps";
import { DataExports } from "@/components/security/DataExports";
import { withDb } from "@/lib/api/with-db";
import { privacySummary } from "@/lib/account/privacy";
import { getRequestUser } from "@/lib/auth/request-user";

/** The privacy dashboard: what Identity holds about you, the apps you've let in, and getting or deleting it all. */
export default async function PrivacyDashboardPage() {
  const user = await getRequestUser();
  if (!user) redirect("/login?return_to=/account/privacy");
  const categories = await withDb(() => privacySummary(user.id));
  return <>
    <section aria-labelledby="privacy-title" className="mx-auto my-8 w-full max-w-3xl space-y-5 rounded-2xl border border-[var(--hairline)] p-6">
      <h1 id="privacy-title" className="text-2xl font-semibold">Your privacy</h1>
      <p className="text-sm opacity-75">What Noirly Identity holds about you, why, and for how long. Apps hold their own data; each app&apos;s access is listed below.</p>
      <ul aria-label="What Identity holds" className="divide-y divide-[var(--hairline)]">
        {categories.map((c) => (
          <li key={c.id} className="py-3">
            <p className="font-medium">{c.label} <span className="text-xs font-normal opacity-75">{c.count === 0 ? "none" : c.count}</span></p>
            <p className="text-sm opacity-75">{c.why}</p>
            <p className="text-xs opacity-75">Kept: {c.kept}</p>
          </li>
        ))}
      </ul>
      <div className="flex flex-wrap gap-4 text-sm">
        <a className="underline" href="/api/auth/export" download>Download all of it</a>
        <a className="underline" href="/delete-account">Close your account</a>
        <a className="underline" href="/account">Back to your account</a>
      </div>
    </section>
    <DataExports />
    <ConnectedApps />
  </>;
}
