"use client";
import { useEffect, useId, useState } from "react";
import { ABSOLUTE_CHOICES, IDLE_CHOICES, type SessionPolicy } from "@/lib/sessions/lifetime-choices";
import { securityRequest } from "./client";

type Loaded = { policy: SessionPolicy; effective?: SessionPolicy; defaultAbsoluteSeconds: number };

function duration(seconds: number) {
  if (seconds % 86_400 === 0) { const d = seconds / 86_400; return d === 1 ? "1 day" : `${d} days`; }
  if (seconds % 3600 === 0) { const h = seconds / 3600; return h === 1 ? "1 hour" : `${h} hours`; }
  return `${Math.round(seconds / 60)} minutes`;
}

/** Lets the account shorten how long its sessions last: after going unused, and in all. */
export function SessionLifetime() {
  const idleId = useId();
  const absoluteId = useId();
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  const [idle, setIdle] = useState("");
  const [absolute, setAbsolute] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  function show(data: Loaded) {
    setLoaded(data);
    setIdle(data.policy.idleSeconds === null ? "" : String(data.policy.idleSeconds));
    setAbsolute(data.policy.absoluteSeconds === null ? "" : String(data.policy.absoluteSeconds));
  }

  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/auth/sessions/policy", { cache: "no-store", signal: controller.signal })
      .then(async (response) => { if (!response.ok) throw new Error(); return response.json() as Promise<Loaded>; })
      .then(show)
      .catch(() => { if (!controller.signal.aborted) setMessage("Unable to load session settings"); });
    return () => controller.abort();
  }, []);

  async function save(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    try {
      show(await securityRequest<Loaded>("/api/auth/sessions/policy", {
        idleSeconds: idle ? Number(idle) : null,
        absoluteSeconds: absolute ? Number(absolute) : null,
      }));
      setMessage("Saved. Your other devices follow it now.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Couldn't save");
    } finally {
      setBusy(false);
    }
  }

  // Keep a saved value that isn't one of the usual choices selectable.
  const idleOptions = [...new Set<number | null>([...IDLE_CHOICES, loaded?.policy.idleSeconds ?? null])];
  const absoluteOptions = [...new Set<number | null>([...ABSOLUTE_CHOICES, loaded?.policy.absoluteSeconds ?? null])]
    .filter((s) => s === null || !loaded || s <= loaded.defaultAbsoluteSeconds);

  return <section aria-labelledby="lifetime-title" className="mx-auto my-8 w-full max-w-3xl space-y-5 rounded-2xl border border-[var(--hairline)] p-6">
    <h2 id="lifetime-title" className="text-xl font-semibold">How long you stay signed in</h2>
    <p className="text-sm opacity-75">Shorter sessions mean a lost or shared device stays signed in for less time. This applies to every device now, not just new sign-ins. Changing it needs a fresh sign-in.</p>
    {loaded?.effective && (loaded.effective.idleSeconds !== loaded.policy.idleSeconds || loaded.effective.absoluteSeconds !== loaded.policy.absoluteSeconds) ? (
      <p className="text-sm">
        An organization you belong to limits this further:{" "}
        {[
          loaded.effective.absoluteSeconds !== null ? `sessions last at most ${duration(loaded.effective.absoluteSeconds)}` : null,
          loaded.effective.idleSeconds !== null ? `sign-out after ${duration(loaded.effective.idleSeconds)} unused` : null,
        ].filter(Boolean).join(", ")}.
      </p>
    ) : null}
    {message && <p role="status" className="text-sm">{message}</p>}
    {!loaded ? (!message && <p role="status">Loading…</p>) : (
      <form onSubmit={(e) => void save(e)} className="flex flex-wrap items-end gap-4">
        <label htmlFor={idleId} className="space-y-1 text-sm">
          <span className="block">Sign out after going unused for</span>
          <select id={idleId} value={idle} disabled={busy} onChange={(e) => setIdle(e.target.value)} className="rounded-xl border border-[var(--hairline)] bg-transparent px-3 py-2">
            {idleOptions.map((s) => <option key={s ?? "never"} value={s ?? ""}>{s === null ? "Never" : duration(s)}</option>)}
          </select>
        </label>
        <label htmlFor={absoluteId} className="space-y-1 text-sm">
          <span className="block">Sign out after, however busy</span>
          <select id={absoluteId} value={absolute} disabled={busy} onChange={(e) => setAbsolute(e.target.value)} className="rounded-xl border border-[var(--hairline)] bg-transparent px-3 py-2">
            {absoluteOptions.map((s) => <option key={s ?? "default"} value={s ?? ""}>{s === null ? `${duration(loaded.defaultAbsoluteSeconds)} (default)` : duration(s)}</option>)}
          </select>
        </label>
        <button type="submit" disabled={busy} className="rounded-xl border border-[var(--hairline)] px-3 py-2 text-sm focus-visible:outline-2 disabled:opacity-50">Save</button>
      </form>
    )}
  </section>;
}
