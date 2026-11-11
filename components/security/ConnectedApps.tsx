"use client";
import { useEffect, useState } from "react";
import type { AppAccessView } from "@/lib/account/app-scopes";
import { securityRequest } from "./client";

const DAY_MS = 86_400_000;

/** "Today", "Yesterday", "3 days ago", or the date once it's a while back. */
function whenText(iso: string) {
  const days = Math.floor((Date.now() - new Date(iso).getTime()) / DAY_MS);
  if (days <= 0) return "today";
  if (days === 1) return "yesterday";
  if (days < 30) return `${days} days ago`;
  return `on ${new Date(iso).toLocaleDateString()}`;
}

/** Every app that has had this account's details: what each can see, and when it last looked. */
export function ConnectedApps() {
  const [apps, setApps] = useState<AppAccessView[] | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  /** Ends the app's sign-ins on every device; Identity and other apps stay signed in. */
  async function signOutEverywhere(app: AppAccessView) {
    setBusy(true);
    setMessage("");
    try {
      await securityRequest("/api/auth/sessions", { action: "sign-out-app", clientId: app.clientId });
      setApps((current) => current?.map((a) => a.clientId === app.clientId ? { ...a, signedIn: false } : a) ?? null);
      setMessage(`Signed out of ${app.name} on every device.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Couldn't sign out");
    } finally {
      setBusy(false);
    }
  }

  /** Takes the app's access away: tokens, sessions, and what it was granted. */
  async function removeAccess(app: AppAccessView) {
    if (!window.confirm(`Remove ${app.name}'s access? It's signed out everywhere, can no longer see your details, and has to ask you again next time you use it.`)) return;
    setBusy(true);
    setMessage("");
    try {
      const result = await securityRequest<{ apps: AppAccessView[] }>("/api/auth/apps", { action: "remove", clientId: app.clientId });
      setApps(result.apps);
      setMessage(`${app.name} no longer has access to your account.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Couldn't remove access");
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/auth/apps", { cache: "no-store", signal: controller.signal })
      .then(async (response) => { if (!response.ok) throw new Error(); return response.json() as Promise<{ apps: AppAccessView[] }>; })
      .then((data) => setApps(data.apps))
      .catch(() => { if (!controller.signal.aborted) setMessage("Unable to load apps"); });
    return () => controller.abort();
  }, []);

  return <section aria-labelledby="apps-title" className="mx-auto my-8 w-full max-w-3xl space-y-5 rounded-2xl border border-[var(--hairline)] p-6">
    <h2 id="apps-title" className="text-xl font-semibold">Apps using your account</h2>
    <p className="text-sm opacity-75">Each app that has signed you in, what it can see about you and since when, and when it last looked. Remove an app&apos;s access and it has to ask you again.</p>
    {message && <p role="status" className="text-sm">{message}</p>}
    {!apps ? (!message && <p role="status">Loading apps…</p>) : apps.length === 0 ? <p className="text-sm opacity-75">No apps have signed you in yet.</p> : (
      <ul aria-label="Apps using your account" className="divide-y divide-[var(--hairline)]">
        {apps.map((app) => (
          <li key={app.clientId} data-app={app.clientId} className="space-y-2 py-4">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <span className="font-medium">
                {app.name}
                <span className="ml-2 text-xs font-normal opacity-75">{app.kind === "mobile" ? "Mobile app" : "Web app"}</span>
              </span>
              {app.signedIn && <span className="flex items-center gap-2">
                <span className="rounded-full border border-[var(--hairline)] px-2 py-0.5 text-xs">Signed in now</span>
                <button type="button" className="rounded-xl border border-[var(--hairline)] px-3 py-1 text-sm focus-visible:outline-2 disabled:opacity-50" disabled={busy} onClick={() => void signOutEverywhere(app)}>
                  Sign out everywhere<span className="sr-only"> of {app.name}</span>
                </button>
              </span>}
            </div>
            <ul aria-label={`What ${app.name} can see`} className="list-disc space-y-0.5 pl-5 text-sm">
              {app.grants.map((grant) => (
                <li key={grant.scope}>
                  {grant.text} <span className="text-xs opacity-75">since <time dateTime={grant.since}>{new Date(grant.since).toLocaleDateString()}</time></span>
                </li>
              ))}
            </ul>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-xs opacity-75">
                Last used <time dateTime={app.lastUsedAt}>{whenText(app.lastUsedAt)}</time> · first <time dateTime={app.firstUsedAt}>{whenText(app.firstUsedAt)}</time>
              </p>
              <button type="button" className="rounded-xl border border-[var(--hairline)] px-3 py-1 text-sm focus-visible:outline-2 disabled:opacity-50" disabled={busy} onClick={() => void removeAccess(app)}>
                Remove access<span className="sr-only"> for {app.name}</span>
              </button>
            </div>
          </li>
        ))}
      </ul>
    )}
  </section>;
}
