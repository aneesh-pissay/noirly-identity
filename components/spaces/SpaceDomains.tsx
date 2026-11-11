"use client";

import { FormEvent, useEffect, useState } from "react";
import { getCsrf } from "@/lib/auth/csrf-client";

type Domain = { domain: string; verified: boolean; policy: "invite_only" | "auto_join"; txtName: string; txtValue: string };

async function post(spaceId: string, body: Record<string, string>) {
  const res = await fetch(`/api/spaces/${spaceId}/domains`, {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json", "x-csrf-token": await getCsrf() },
    body: JSON.stringify(body),
  });
  const data = (await res.json()) as { domains?: Domain[]; message?: string };
  if (!res.ok || !data.domains) throw new Error(data.message ?? "Something went wrong");
  return data.domains;
}

/** A space's verified business domains: add, verify by DNS TXT, choose who may join, remove (owners). */
export function SpaceDomains({ spaceId, isOwner }: { spaceId: string; isOwner: boolean }) {
  const [domains, setDomains] = useState<Domain[] | null>(null);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    void fetch(`/api/spaces/${spaceId}/domains`, { credentials: "include", cache: "no-store", signal: controller.signal })
      .then(async (res) => (res.ok ? ((await res.json()) as { domains: Domain[] }).domains : []))
      .then(setDomains)
      .catch(() => undefined);
    return () => controller.abort();
  }, [spaceId]);

  async function act(body: Record<string, string>, done: string) {
    setBusy(true);
    setMessage("");
    try {
      setDomains(await post(spaceId, body));
      setMessage(done);
    } catch (error) {
      setMessage((error as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (!domains || (!isOwner && domains.length === 0)) return null;
  return (
    <section aria-labelledby={`domains-${spaceId}`} className="space-y-3 rounded-xl border border-[var(--hairline)] p-4">
      <h3 id={`domains-${spaceId}`} className="text-sm font-semibold">Business domains</h3>
      <p className="text-xs text-[var(--muted-foreground)]">
        Prove the space owns a domain with a DNS TXT record. Then you can let anyone with a confirmed address there join without an invitation.
      </p>
      {message ? <p role="status" className="text-xs">{message}</p> : null}
      <ul className="space-y-2">
        {domains.map((d) => (
          <li key={d.domain} className="space-y-1 text-sm">
            <p className="font-medium">
              {d.domain} <span className="text-xs font-normal text-[var(--muted-foreground)]">{d.verified ? "verified" : "not verified yet"}</span>
            </p>
            {!d.verified ? (
              <p className="break-all font-mono text-[11px] text-[var(--muted-foreground)]">TXT {d.txtName} = {d.txtValue}</p>
            ) : null}
            {isOwner ? (
              <div className="flex flex-wrap items-center gap-2 text-xs">
                {!d.verified ? (
                  <button type="button" className="underline" disabled={busy} onClick={() => void act({ action: "verify", domain: d.domain }, `${d.domain} verified.`)}>
                    Check DNS now
                  </button>
                ) : (
                  <label className="flex items-center gap-1">
                    Who may join through it
                    <select
                      value={d.policy}
                      disabled={busy}
                      onChange={(e) => void act({ action: "policy", domain: d.domain, policy: e.target.value }, "Saved.")}
                      className="rounded border border-[var(--hairline)] bg-transparent px-1"
                    >
                      <option value="invite_only">Only people invited</option>
                      <option value="auto_join">Anyone with an address there</option>
                    </select>
                  </label>
                )}
                <button type="button" className="underline" disabled={busy} onClick={() => void act({ action: "remove", domain: d.domain }, `${d.domain} removed.`)}>
                  Remove<span className="sr-only"> {d.domain}</span>
                </button>
              </div>
            ) : null}
          </li>
        ))}
      </ul>
      {isOwner ? (
        <form
          className="flex flex-wrap gap-2"
          onSubmit={(event: FormEvent) => {
            event.preventDefault();
            if (!input.trim()) return;
            void act({ action: "add", domain: input.trim() }, "Added. Publish the TXT record, then check DNS.").then(() => setInput(""));
          }}
        >
          <label className="sr-only" htmlFor={`domain-input-${spaceId}`}>Domain</label>
          <input
            id={`domain-input-${spaceId}`}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="example.com"
            className="h-9 min-w-[12rem] flex-1 rounded-xl border border-[var(--hairline)] bg-transparent px-3 text-sm"
          />
          <button type="submit" disabled={busy || !input.trim()} className="rounded-xl border border-[var(--hairline)] px-3 text-sm disabled:opacity-50">
            Add domain
          </button>
        </form>
      ) : null}
    </section>
  );
}
