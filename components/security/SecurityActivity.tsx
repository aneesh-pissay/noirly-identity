"use client";
import { useEffect, useState } from "react";
import { ACTIVITY_KINDS, ACTIVITY_KIND_LABEL, type ActivityItem, type ActivityKind } from "@/lib/audit/activity";

type Page = { events: ActivityItem[]; nextBefore: number | null };
const button = "rounded-xl border border-[var(--hairline)] px-4 py-2 text-sm focus-visible:outline-2 disabled:opacity-50";

async function fetchPage(kind: ActivityKind | "", before: number | null, signal?: AbortSignal): Promise<Page> {
  const params = new URLSearchParams();
  if (kind) params.set("kind", kind);
  if (before) params.set("before", String(before));
  const response = await fetch(`/api/auth/activity?${params}`, { cache: "no-store", signal });
  if (!response.ok) throw new Error("Unable to load security activity");
  return response.json() as Promise<Page>;
}

/** Recent sign-ins and security changes on this account, with anything unfamiliar picked out. */
export function SecurityActivity() {
  const [kind, setKind] = useState<ActivityKind | "">("");
  const [events, setEvents] = useState<ActivityItem[] | null>(null);
  const [nextBefore, setNextBefore] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    void fetchPage(kind, null, controller.signal)
      .then((page) => { setEvents(page.events); setNextBefore(page.nextBefore); setMessage(""); })
      .catch(() => { if (!controller.signal.aborted) setMessage("Unable to load security activity"); });
    return () => controller.abort();
  }, [kind]);

  async function more() {
    setBusy(true);
    try {
      const page = await fetchPage(kind, nextBefore);
      setEvents((current) => [...(current ?? []), ...page.events]);
      setNextBefore(page.nextBefore);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to load security activity");
    } finally {
      setBusy(false);
    }
  }

  const notable = events?.filter((e) => e.notable).length ?? 0;

  return <section aria-labelledby="activity-title" className="mx-auto my-8 w-full max-w-3xl space-y-5 rounded-2xl border border-[var(--hairline)] p-6">
    <h2 id="activity-title" className="text-xl font-semibold">Security activity</h2>
    <p className="text-sm opacity-75">Sign-ins and security changes on your account. If something here wasn&apos;t you, <a href="#password" className="underline">change your password</a> and check your authenticator and passkeys above.</p>
    <div role="group" aria-label="Show" className="flex flex-wrap gap-2">
      {(["", ...ACTIVITY_KINDS] as const).map((k) => (
        <button key={k || "all"} type="button" aria-pressed={kind === k} className={`${button} aria-pressed:bg-[var(--surface-2)] aria-pressed:font-medium`} onClick={() => { setEvents(null); setKind(k); }}>
          {k ? ACTIVITY_KIND_LABEL[k] : "Everything"}
        </button>
      ))}
    </div>
    {message && <p role="status" className="text-sm">{message}</p>}
    {!events ? <p role="status">Loading security activity…</p> : <>
      {notable > 0 && <p className="text-sm">{notable} {notable === 1 ? "item is" : "items are"} worth a look: marked below.</p>}
      {events.length === 0 && <p className="text-sm opacity-75">Nothing here yet.</p>}
      <ol aria-label="Security activity" className="divide-y divide-[var(--hairline)]">
        {events.map((e) => (
          <li key={e.seq} data-action={e.action} data-notable={e.notable || undefined} className="flex flex-col gap-1 py-3">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <span className={e.notable ? "font-medium" : undefined}>
                {e.notable && <span aria-hidden className="mr-2 text-[var(--accent)]">●</span>}
                {e.title}
                {e.newDevice && <span className="ml-2 rounded-full border border-[var(--hairline)] px-2 py-0.5 text-xs">New device</span>}
              </span>
              <time dateTime={e.at} className="text-xs opacity-75">{new Date(e.at).toLocaleString()}</time>
            </div>
            <p className="text-xs opacity-75">
              {[e.device, e.ipAddress, e.app ? `via ${e.app}` : null].filter(Boolean).join(" · ")}
            </p>
          </li>
        ))}
      </ol>
      {nextBefore && <button type="button" className={button} disabled={busy} onClick={() => void more()}>{busy ? "Loading…" : "Show older"}</button>}
    </>}
  </section>;
}
