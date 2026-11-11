"use client";

import { useCallback, useEffect, useState } from "react";
import { AuthShell } from "@noirly-dev/ui";
import { AuthLogo } from "@/components/AuthLogo";
import { Notice, TextLink } from "@/components/auth-ui";
import { getCsrf } from "@/lib/auth/csrf-client";

type Item = { clientId: string; attempts: number; lastError: string | null };
type Deletion = { sub: string; deletedAt: string; state: "confirmed" | "pending" | "failed"; delivered: Array<{ clientId: string; at: string }>; pending: Item[]; failed: Item[] };

/** Admin: which apps confirmed each account deletion, and retrying the rest. */
export function AdminDeletions() {
  const [state, setState] = useState("");
  const [deletions, setDeletions] = useState<Deletion[]>([]);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    const res = await fetch(`/api/admin/deletions${state ? `?state=${state}` : ""}`, { credentials: "include", cache: "no-store" });
    const data = (await res.json()) as { deletions?: Deletion[]; message?: string };
    if (!res.ok) throw new Error(data.message ?? "Couldn't load deletions");
    return data.deletions ?? [];
  }, [state]);

  useEffect(() => {
    let live = true;
    load().then((d) => { if (live) setDeletions(d); }).catch((e: Error) => { if (live) setError(e.message); });
    return () => { live = false; };
  }, [load]);

  async function retry(sub: string) {
    setError(null);
    try {
      const res = await fetch("/api/admin/deletions", { method: "POST", credentials: "include", headers: { "content-type": "application/json", "x-csrf-token": await getCsrf() }, body: JSON.stringify({ sub }) });
      const data = (await res.json()) as Deletion & { message?: string };
      if (!res.ok) throw new Error(data.message ?? "Retry failed");
      setDeletions((list) => list.map((d) => (d.sub === sub ? data : d)));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Retry failed");
    }
  }

  return (
    <AuthShell logo={<AuthLogo />} title="Account deletions" lead="Which apps confirmed each deletion, for 90 days." size="lg" align="top" className="py-8">
      <div className="space-y-4">
        {error && <Notice tone="error">{error}</Notice>}
        <label className="flex items-center gap-2 text-sm">Show
          <select value={state} onChange={(e) => setState(e.target.value)} className="h-9 rounded-xl border border-[var(--hairline)] bg-transparent px-2 text-sm">
            <option value="">All</option><option value="pending">Still retrying</option><option value="failed">Gave up</option><option value="confirmed">Confirmed</option>
          </select>
        </label>
        {deletions.length === 0 ? <p className="text-sm opacity-75">No deletions here.</p> : (
          <ul className="space-y-3 text-sm">
            {deletions.map((d) => (
              <li key={d.sub} className="rounded-xl border border-[var(--hairline)] p-3">
                <p><code>{d.sub}</code>, deleted {new Date(d.deletedAt).toLocaleString()}: <strong>{d.state === "confirmed" ? "every app confirmed" : d.state === "pending" ? "still retrying" : "some apps never confirmed"}</strong></p>
                {d.delivered.length > 0 && <p className="text-xs opacity-75">Confirmed: {d.delivered.map((x) => x.clientId).join(", ")}</p>}
                {[...d.pending, ...d.failed].map((x) => <p key={x.clientId} className="text-xs">{x.clientId}: {x.attempts} attempt(s), {x.lastError ?? "no answer"}</p>)}
                {d.state !== "confirmed" && <button type="button" onClick={() => void retry(d.sub)} className="mt-2 rounded-xl border border-[var(--hairline)] px-3 py-1 text-xs">Retry now</button>}
              </li>
            ))}
          </ul>
        )}
        <TextLink href="/admin/audit">Audit log</TextLink>
      </div>
    </AuthShell>
  );
}
