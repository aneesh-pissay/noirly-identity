"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import type { DeviceSession } from "@/lib/sessions/devices";
import { securityRequest } from "./client";

const button = "rounded-xl border border-[var(--hairline)] px-3 py-2 text-sm focus-visible:outline-2 disabled:opacity-50";

type Result = { count: number; includingThisOne: boolean; sessions: DeviceSession[] };

/** Every browser and device signed in to the account, with sign-out of one, several or all others. */
export function DeviceSessions() {
  const router = useRouter();
  const [sessions, setSessions] = useState<DeviceSession[] | null>(null);
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/auth/sessions", { cache: "no-store", signal: controller.signal })
      .then(async (response) => { if (!response.ok) throw new Error(); return response.json() as Promise<{ sessions: DeviceSession[] }>; })
      .then((data) => setSessions(data.sessions))
      .catch(() => { if (!controller.signal.aborted) setMessage("Unable to load your devices"); });
    return () => controller.abort();
  }, []);

  async function signOut(body: Record<string, unknown>) {
    setBusy(true);
    setMessage("");
    try {
      const result = await securityRequest<Result>("/api/auth/sessions", body);
      if (result.includingThisOne) {
        // This device was among them: it's signed out too.
        router.push("/login");
        return;
      }
      setSessions(result.sessions);
      setChosen(new Set());
      setMessage(result.count === 0 ? "Nothing to sign out." : `Signed out ${result.count === 1 ? "1 device" : `${result.count} devices`}.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Couldn't sign out");
    } finally {
      setBusy(false);
    }
  }

  async function signOutApp(sessionId: string, app: { clientId: string; name: string }) {
    setBusy(true);
    setMessage("");
    try {
      const result = await securityRequest<{ ended: number; sessions: DeviceSession[] }>("/api/auth/sessions", { action: "sign-out-app", clientId: app.clientId, sessionId });
      setSessions(result.sessions);
      setMessage(result.ended ? `Signed out of ${app.name} on that device.` : `${app.name} was already signed out there.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Couldn't sign out");
    } finally {
      setBusy(false);
    }
  }

  const toggle = (id: string) => setChosen((current) => {
    const next = new Set(current);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    return next;
  });
  const others = sessions?.filter((s) => !s.current).length ?? 0;

  return <section aria-labelledby="devices-title" className="mx-auto my-8 w-full max-w-3xl space-y-5 rounded-2xl border border-[var(--hairline)] p-6">
    <h2 id="devices-title" className="text-xl font-semibold">Devices and sessions</h2>
    <p className="text-sm opacity-75">Everywhere your account is signed in. Don&apos;t recognise one? Sign it out and change your password. Signing out a device also signs it out of the apps it opened; you can also sign out of one app and stay signed in to the rest.</p>
    {message && <p role="status" className="text-sm">{message}</p>}
    {!sessions ? <p role="status">Loading devices…</p> : <>
      <ul aria-label="Signed-in devices" className="divide-y divide-[var(--hairline)]">
        {sessions.map((s) => (
          <li key={s.id} data-current={s.current || undefined} className="flex items-start gap-3 py-3">
            <input type="checkbox" className="mt-1" aria-label={`Choose ${s.device}${s.current ? " (this device)" : ""}`} checked={chosen.has(s.id)} disabled={busy} onChange={() => toggle(s.id)} />
            <div className="min-w-0 flex-1 space-y-0.5">
              <p className="font-medium">
                {s.device}
                {s.current && <span className="ml-2 rounded-full border border-[var(--hairline)] px-2 py-0.5 text-xs font-normal">This device</span>}
              </p>
              <p className="text-xs opacity-75">{[s.place, s.ipAddress].filter(Boolean).join(" · ") || "Place unknown"}</p>
              <p className="text-xs opacity-75">
                Active {new Date(s.lastActiveAt).toLocaleString()} · signed in {new Date(s.signedInAt).toLocaleDateString()}
                {s.how ? ` · ${s.how.replace(/^Signed in with /, "with ")}` : ""}
              </p>
              {s.apps.length > 0 && <ul aria-label={`Apps opened on ${s.device}`} className="mt-1 space-y-1">
                {s.apps.map((app) => (
                  <li key={app.clientId} className="flex flex-wrap items-center gap-2 text-xs">
                    <span>{app.name}</span>
                    <span className="opacity-75">{app.signedIn ? "signed in" : "signed out"}</span>
                    {app.signedIn && <button type="button" className="rounded-lg border border-[var(--hairline)] px-2 py-0.5 focus-visible:outline-2 disabled:opacity-50" disabled={busy} onClick={() => void signOutApp(s.id, app)}>
                      Sign out of {app.name}<span className="sr-only"> on {s.device}</span>
                    </button>}
                  </li>
                ))}
              </ul>}
            </div>
            {!s.current && <button type="button" className={button} disabled={busy} onClick={() => void signOut({ action: "sign-out", ids: [s.id] })}>Sign out <span className="sr-only">{s.device}</span></button>}
          </li>
        ))}
      </ul>
      <div className="flex flex-wrap gap-2">
        <button type="button" className={button} disabled={busy || chosen.size === 0} onClick={() => void signOut({ action: "sign-out", ids: [...chosen] })}>
          Sign out chosen{chosen.size ? ` (${chosen.size})` : ""}
        </button>
        <button type="button" className={button} disabled={busy || others === 0} onClick={() => void signOut({ action: "sign-out-others" })}>Sign out all other devices</button>
      </div>
    </>}
  </section>;
}
