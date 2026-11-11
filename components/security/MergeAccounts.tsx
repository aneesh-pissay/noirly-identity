"use client";
import { useEffect, useState } from "react";
import { FormField } from "@/components/auth-ui";
import type { MergePlan, MergeRequestView } from "@/lib/account/merge-plan";
import { securityRequest } from "./client";

const button = "rounded-xl border border-[var(--hairline)] px-4 py-2 text-sm focus-visible:outline-2 disabled:opacity-50";

/** Bring another account of yours into this one: ask, confirm from the other account's email, then review and complete. */
export function MergeAccounts() {
  const [merge, setMerge] = useState<MergeRequestView | null | undefined>(undefined);
  const [email, setEmail] = useState("");
  const [done, setDone] = useState<MergePlan | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/auth/merge", { cache: "no-store", signal: controller.signal })
      .then(async (response) => { if (!response.ok) throw new Error(); return response.json() as Promise<{ merge: MergeRequestView | null }>; })
      .then((data) => setMerge(data.merge))
      .catch(() => { if (!controller.signal.aborted) setMessage("Unable to load account merging"); });
    return () => controller.abort();
  }, []);

  async function run(body: Record<string, unknown>, after: (data: { merge?: MergeRequestView | null; plan?: MergePlan }) => void) {
    setBusy(true);
    setMessage("");
    try {
      after(await securityRequest("/api/auth/merge", body));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }

  return <section aria-labelledby="merge-title" className="mx-auto my-8 w-full max-w-3xl space-y-5 rounded-2xl border border-[var(--hairline)] p-6">
    <h2 id="merge-title" className="text-xl font-semibold">Merge another account into this one</h2>
    <p className="text-sm opacity-75">If you have two Noirly accounts, bring the other one&apos;s sign-ins, addresses and spaces here and close it. Apps are told, so they can move what they hold. Asking and completing need a sign-in within the last five minutes.</p>
    {message && <p role="status" className="text-sm">{message}</p>}
    {done ? (
      <div role="status" className="space-y-2 text-sm">
        <p className="font-medium">Merged. The other account is closed.</p>
        {done.moves.length > 0 && <ul className="list-disc pl-5">{done.moves.map((line) => <li key={line}>{line}</li>)}</ul>}
      </div>
    ) : merge === undefined ? (!message && <p role="status">Loading…</p>) : merge === null ? (
      <form className="flex flex-col gap-3" onSubmit={(event) => { event.preventDefault(); const value = email.trim(); void run({ action: "request", email: value }, (data) => { setMerge(data.merge ?? null); setEmail(""); setMessage(`If ${value} belongs to another Noirly account, we've sent it a link. Open it to confirm, then come back here.`); }); }}>
        <FormField label="The other account's email address" type="email" value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="off" maxLength={320} />
        <button type="submit" className={`${button} self-start`} disabled={busy || !email.trim()}>Send confirmation link</button>
      </form>
    ) : merge.status === "awaiting_confirmation" || !merge.plan ? (
      <div className="space-y-3 text-sm">
        <p>Waiting for confirmation from {merge.otherEmail}. If it belongs to another Noirly account, we sent a link to that account&apos;s email: open it, then reload this page.</p>
        <button type="button" className={button} disabled={busy} onClick={() => void run({ action: "cancel", id: merge.id }, () => setMerge(null))}>Cancel</button>
      </div>
    ) : (
      <div className="space-y-4 text-sm">
        <p>Confirmed from {merge.otherEmail}. Review what happens, then complete it before {new Date(merge.expiresAt).toLocaleString()}.</p>
        <div>
          <h3 className="font-medium">Comes to this account</h3>
          {merge.plan.moves.length ? <ul aria-label="Comes to this account" className="mt-1 list-disc pl-5">{merge.plan.moves.map((line) => <li key={line}>{line}</li>)}</ul> : <p className="mt-1 opacity-75">Nothing beyond its history.</p>}
        </div>
        <div>
          <h3 className="font-medium">Doesn&apos;t come across</h3>
          <ul aria-label="Doesn't come across" className="mt-1 list-disc pl-5">{merge.plan.drops.map((line) => <li key={line}>{line}</li>)}</ul>
        </div>
        <p className="opacity-75">This can&apos;t be undone.</p>
        <div className="flex flex-wrap gap-2">
          <button type="button" className={button} disabled={busy} onClick={() => void run({ action: "complete", id: merge.id }, (data) => { setDone(data.plan ?? { moves: [], drops: [] }); setMerge(null); })}>{busy ? "Merging…" : "Merge and close the other account"}</button>
          <button type="button" className={button} disabled={busy} onClick={() => void run({ action: "cancel", id: merge.id }, () => setMerge(null))}>Cancel</button>
        </div>
      </div>
    )}
  </section>;
}
