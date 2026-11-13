import Link from "next/link";
import { redirect } from "next/navigation";
import { AlertTriangle, ArrowRight, CheckCircle2 } from "lucide-react";
import { ACCOUNT_AREAS } from "@/components/account/areas";
import { AccountPageHeader } from "@/components/account/AccountPageHeader";
import { HashForward } from "@/components/account/HashForward";
import { withDb } from "@/lib/api/with-db";
import { accountOverview } from "@/lib/account/overview";
import { getRequestUser } from "@/lib/auth/request-user";

/** Links from apps and emails that used to land on the one long page, and the page that now has what they point at. */
const SECURITY_PARAMS = ["linked", "link_error", "provider", "mfa_for", "return_to"];

/** Account home: is the account safe, and where everything is. */
export default async function AccountHomePage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const user = await getRequestUser();
  if (!user) redirect("/login?return_to=/account");

  // Back from linking a provider, or sent by an app that needs a second step: that's the Security page now.
  const params = await searchParams;
  if (SECURITY_PARAMS.some((key) => typeof params[key] === "string")) {
    const query = new URLSearchParams();
    for (const key of SECURITY_PARAMS) {
      const value = params[key];
      if (typeof value === "string") query.set(key, value.slice(0, 500));
    }
    redirect(`/account/security?${query}`);
  }

  const overview = await withDb(() => accountOverview(user.id));
  const summary: Record<string, string> = {
    "/account/profile": user.email,
    "/account/security": `${overview.secondStep.on ? "Second step on" : "No second step yet"} · ${overview.recovery ? "recovery set" : "no recovery address"}`,
    "/account/devices": `${overview.devices} signed in`,
    "/account/privacy": overview.apps === 1 ? "1 app can see your details" : `${overview.apps} apps can see your details`,
    "/account/manage": overview.spaces === 1 ? "In 1 space" : `In ${overview.spaces} spaces`,
  };
  const description: Record<string, string> = {
    "/account/profile": "Your name, photo, email addresses, phone, language and accessibility.",
    "/account/security": "Your password, ways to sign in, two-step verification and recovery.",
    "/account/devices": "Where you're signed in, how long you stay signed in, and recent activity.",
    "/account/privacy": "Apps you've let in, what Noirly keeps about you, and getting your data.",
    "/account/manage": "Spaces, merging two accounts, freezing, and closing your account.",
  };

  return (
    <>
      <HashForward />
      <AccountPageHeader title={`Hi, ${user.firstName || user.displayName}`} lead="Your Noirly account: one sign-in for Flow, Ledger and every Noirly app." />

      <section aria-labelledby="checkup-title" className="mb-8 rounded-2xl border border-[var(--hairline)] p-6">
        <h2 id="checkup-title" className="text-xl font-semibold">Security checkup</h2>
        {overview.checkup.length === 0 ? (
          <p className="mt-3 flex items-start gap-3 text-sm">
            <CheckCircle2 size={20} aria-hidden className="mt-0.5 shrink-0 text-[var(--success,#3ddc97)]" />
            <span>Your account is in good shape: you have a second step and a recovery address, and nothing needs fixing.</span>
          </p>
        ) : (
          <>
            <p className="mt-1 text-sm text-[var(--muted-foreground)]">
              {overview.checkup.length === 1 ? "One thing to look at." : `${overview.checkup.length} things to look at, most important first.`}
            </p>
            <ul className="mt-4 divide-y divide-[var(--hairline)]">
              {overview.checkup.map((item) => (
                <li key={item.id} className="flex flex-col gap-3 py-4 first:pt-0 last:pb-0 sm:flex-row sm:items-center sm:justify-between">
                  <div className="flex items-start gap-3">
                    <AlertTriangle size={20} aria-hidden className={`mt-0.5 shrink-0 ${item.severity === "high" ? "text-red-400" : "text-[var(--accent)]"}`} />
                    <div>
                      <p className="font-medium">{item.title}</p>
                      <p className="text-sm text-[var(--muted-foreground)]">{item.detail}</p>
                    </div>
                  </div>
                  <Link href={item.href} className="inline-flex shrink-0 items-center gap-1 self-start rounded-xl border border-[var(--hairline)] px-3 py-1.5 text-sm hover:bg-[var(--surface-2)] sm:self-center">
                    Fix it <ArrowRight size={14} aria-hidden />
                  </Link>
                </li>
              ))}
            </ul>
          </>
        )}
      </section>

      <ul aria-label="Account areas" className="grid gap-4 sm:grid-cols-2">
        {ACCOUNT_AREAS.filter((area) => area.href !== "/account").map((area) => {
          const Icon = area.icon;
          return (
            <li key={area.href}>
              <Link href={area.href} className="group flex h-full flex-col rounded-2xl border border-[var(--hairline)] p-5 transition-colors hover:border-[var(--accent)]">
                <span className="flex items-center justify-between gap-3">
                  <span className="flex items-center gap-3 font-medium">
                    <Icon size={18} aria-hidden /> {area.label}
                  </span>
                  <ArrowRight size={16} aria-hidden className="text-[var(--muted-foreground)] transition-transform group-hover:translate-x-0.5" />
                </span>
                <span className="mt-2 text-sm text-[var(--muted-foreground)]">{description[area.href]}</span>
                <span className="mt-3 text-xs font-medium">{summary[area.href]}</span>
              </Link>
            </li>
          );
        })}
      </ul>
    </>
  );
}
