"use client";
import { useEffect, useState } from "react";
import { securityRequest } from "./client";

type Export = { id: string; status: "collecting" | "ready"; requestedAt: string; readyAt: string | null; expiresAt: string; apps: Array<{ name: string; status: string }> };

/** Your data from Identity and every Noirly app you use, in one download. */
export function DataExports() {
  const [exports, setExports] = useState<Export[] | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/auth/data-export", { cache: "no-store", signal: controller.signal })
      .then(async (res) => (res.ok ? ((await res.json()) as { exports: Export[] }).exports : []))
      .then(setExports)
      .catch(() => undefined);
    return () => controller.abort();
  }, []);

  async function start() {
    setBusy(true);
    setMessage("");
    try {
      const created = await securityRequest<Export>("/api/auth/data-export", {});
      setExports((current) => [created, ...(current ?? [])]);
      setMessage(created.status === "ready" ? "Ready to download." : "Collecting from your apps; we'll email you when it's ready.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "That didn't work");
    } finally {
      setBusy(false);
    }
  }

  return <section aria-labelledby="exports-title" className="mx-auto my-8 w-full max-w-3xl space-y-3 rounded-2xl border border-[var(--hairline)] p-6">
    <h2 id="exports-title" className="text-xl font-semibold">Your data from every Noirly app</h2>
    <p className="text-sm opacity-75">One download with what Noirly Identity and each Noirly app you use hold about you. Apps answer within minutes; we email you when it&apos;s ready. Downloads last a week.</p>
    {message && <p role="status" className="text-sm">{message}</p>}
    <button type="button" disabled={busy} onClick={() => void start()} className="rounded-xl border border-[var(--hairline)] px-3 py-2 text-sm disabled:opacity-50">Get my data</button>
    {exports?.length ? (
      <ul className="space-y-2 text-sm">
        {exports.map((e) => (
          <li key={e.id}>
            Asked {new Date(e.requestedAt).toLocaleString()}: {e.status === "ready" ? <a className="underline" href={`/api/auth/data-export?download=${e.id}`} download>download</a> : "collecting"}
            {e.apps.length ? <span className="text-xs opacity-75"> ({e.apps.map((a) => `${a.name}: ${a.status.replace("_", " ")}`).join(", ")})</span> : null}
          </li>
        ))}
      </ul>
    ) : null}
  </section>;
}
