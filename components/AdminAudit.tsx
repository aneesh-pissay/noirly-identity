"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { AuthShell } from "@noirly-dev/ui";
import { AuthLogo } from "@/components/AuthLogo";
import { Notice, TextLink } from "@/components/auth-ui";
import { getCsrf } from "@/lib/auth/csrf-client";

type Event = { id: string; stream: string; at: string; action: string; actorId: string | null; subjectId: string | null; clientId: string | null; ipAddress: string | null; data: unknown };
type Rule = { id: string; name: string; actions: string[]; emails: string[]; enabled: boolean };
type Retention = { accountDays: number | null; adminDays: number | null };

const input = "h-9 rounded-xl border border-[var(--hairline)] bg-transparent px-2 text-sm";

async function post<T>(url: string, method: "POST" | "PATCH", body: unknown): Promise<T> {
  const res = await fetch(url, { method, credentials: "include", headers: { "content-type": "application/json", "x-csrf-token": await getCsrf() }, body: JSON.stringify(body) });
  const data = (await res.json()) as T & { message?: string };
  if (!res.ok) throw new Error(data.message ?? "That didn't work");
  return data;
}

/** Admin: search the identity event log, alert rules on chosen events, retention and export. */
export function AdminAudit({ initial }: { initial: Record<string, string> }) {
  const [filters, setFilters] = useState<Record<string, string>>({ action: initial.action ?? "", email: initial.email ?? "", subjectId: initial.subjectId ?? "", stream: "", ip: "", clientId: "", from: "", to: "" });
  const [events, setEvents] = useState<Event[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [rules, setRules] = useState<Rule[]>([]);
  const [retention, setRetention] = useState<Retention | null>(null);
  const [rule, setRule] = useState({ name: "", actions: "", emails: "" });
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const search = useCallback(async (before?: string) => {
    const query = new URLSearchParams(Object.entries(filters).filter(([, v]) => v.trim()));
    if (before) query.set("before", before);
    const res = await fetch(`/api/admin/events?${query}`, { credentials: "include", cache: "no-store" });
    const data = (await res.json()) as { events?: Event[]; nextBefore?: string | null; message?: string };
    if (!res.ok) throw new Error(data.message ?? "Search failed");
    return data;
  }, [filters]);

  useEffect(() => {
    let alive = true;
    void Promise.all([
      fetch("/api/admin/audit/alerts", { credentials: "include", cache: "no-store" }).then((r) => r.json() as Promise<{ rules?: Rule[] }>),
      fetch("/api/admin/audit", { credentials: "include", cache: "no-store" }).then((r) => r.json() as Promise<Retention>),
    ]).then(([r, ret]) => { if (alive) { setRules(r.rules ?? []); setRetention(ret); } }).catch(() => undefined);
    return () => { alive = false; };
    // Load once; searches run on submit.
  }, []);

  async function run(before?: string) {
    setError(null);
    try {
      const data = await search(before);
      setEvents((current) => (before ? [...current, ...(data.events ?? [])] : data.events ?? []));
      setNext(data.nextBefore ?? null);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  const exportUrl = (kind: string, format: string) => {
    const q = new URLSearchParams({ export: kind, format, ...(filters.from ? { from: filters.from } : {}), ...(filters.to ? { to: filters.to } : {}) });
    return `/api/admin/audit?${q}`;
  };

  return (
    <AuthShell logo={<AuthLogo />} title="Audit log" lead="Every sign-in, change and admin action, hash-chained so tampering shows." size="lg" align="top" className="py-8" footer={<TextLink href="/account">Back to account</TextLink>}>
      <form className="flex flex-wrap gap-2" onSubmit={(e: FormEvent) => { e.preventDefault(); void run(); }}>
        {(["action", "email", "stream", "clientId", "ip"] as const).map((key) => (
          <input key={key} aria-label={key} placeholder={key === "action" ? "action or family (auth.)" : key} value={filters[key]} onChange={(e) => setFilters((f) => ({ ...f, [key]: e.target.value }))} className={input} />
        ))}
        <input aria-label="from" type="date" value={filters.from} onChange={(e) => setFilters((f) => ({ ...f, from: e.target.value }))} className={input} />
        <input aria-label="to" type="date" value={filters.to} onChange={(e) => setFilters((f) => ({ ...f, to: e.target.value }))} className={input} />
        <button type="submit" className="rounded-xl border border-[var(--hairline)] px-3 text-sm">Search</button>
      </form>
      {error ? <Notice tone="error">{error}</Notice> : null}
      {notice ? <Notice tone="success">{notice}</Notice> : null}
      <ul aria-label="Events" className="mt-4 divide-y divide-[var(--hairline)] text-xs">
        {events.map((e) => (
          <li key={e.id} className="py-2">
            <span className="font-mono">{new Date(e.at).toLocaleString()}</span> · <strong>{e.action}</strong> · {e.stream}
            {e.subjectId ? ` · account ${e.subjectId}` : ""}{e.actorId && e.actorId !== e.subjectId ? ` · by ${e.actorId}` : ""}{e.clientId ? ` · ${e.clientId}` : ""}{e.ipAddress ? ` · ${e.ipAddress}` : ""}
            {e.data ? <pre className="mt-1 overflow-x-auto whitespace-pre-wrap text-[11px] text-[var(--muted-foreground)]">{JSON.stringify(e.data)}</pre> : null}
          </li>
        ))}
      </ul>
      {next ? <button type="button" className="text-sm underline" onClick={() => void run(next)}>Older</button> : null}

      <section aria-labelledby="export-title" className="mt-8 space-y-2 border-t border-[var(--hairline)] pt-6 text-sm">
        <h2 id="export-title" className="text-lg font-semibold">Export</h2>
        <p className="text-xs text-[var(--muted-foreground)]">The dates above (or the last 30 days), with each event&apos;s hash.</p>
        <p className="flex flex-wrap gap-3">
          <a className="underline" href={exportUrl("auth", "jsonl")}>Sign-in events (JSON lines)</a>
          <a className="underline" href={exportUrl("auth", "csv")}>Sign-in events (CSV)</a>
          <a className="underline" href={exportUrl("admin", "jsonl")}>Admin log (JSON lines)</a>
          <a className="underline" href={exportUrl("admin", "csv")}>Admin log (CSV)</a>
        </p>
      </section>

      <section aria-labelledby="retention-title" className="mt-6 space-y-2 text-sm">
        <h2 id="retention-title" className="text-lg font-semibold">Retention</h2>
        {retention ? (
          <form className="flex flex-wrap items-end gap-2" onSubmit={(e: FormEvent) => {
            e.preventDefault();
            void post<Retention>("/api/admin/audit", "PATCH", retention).then(setRetention).then(() => setNotice("Retention saved.")).catch((err: Error) => setError(err.message));
          }}>
            {(["accountDays", "adminDays"] as const).map((key) => (
              <label key={key} className="text-xs">{key === "accountDays" ? "Account events, days" : "Admin and system events, days"}
                <input type="number" min={90} max={3650} placeholder="forever" value={retention[key] ?? ""} onChange={(e) => setRetention((r) => ({ ...r!, [key]: e.target.value ? Number(e.target.value) : null }))} className={`${input} ml-2 w-28`} />
              </label>
            ))}
            <button type="submit" className="rounded-xl border border-[var(--hairline)] px-3 text-sm">Save</button>
          </form>
        ) : null}
      </section>

      <section aria-labelledby="rules-title" className="mt-6 space-y-2 text-sm">
        <h2 id="rules-title" className="text-lg font-semibold">Alerts</h2>
        <ul className="space-y-1 text-xs">
          {rules.map((r) => (
            <li key={r.id}>
              <strong>{r.name}</strong>: {r.actions.join(", ")} → {r.emails.join(", ")}
              <button type="button" className="ml-2 underline" onClick={() => void post<{ rules: Rule[] }>("/api/admin/audit/alerts", "POST", { action: "delete", id: r.id }).then((d) => setRules(d.rules)).catch((err: Error) => setError(err.message))}>Delete</button>
            </li>
          ))}
        </ul>
        <form className="flex flex-wrap gap-2" onSubmit={(e: FormEvent) => {
          e.preventDefault();
          void post<{ rules: Rule[] }>("/api/admin/audit/alerts", "POST", { action: "save", name: rule.name, actions: rule.actions.split(/[\s,]+/).filter(Boolean), emails: rule.emails.split(/[\s,]+/).filter(Boolean) })
            .then((d) => { setRules(d.rules); setRule({ name: "", actions: "", emails: "" }); setNotice("Alert saved."); })
            .catch((err: Error) => setError(err.message));
        }}>
          <input aria-label="Rule name" placeholder="Name" value={rule.name} onChange={(e) => setRule((r) => ({ ...r, name: e.target.value }))} className={input} />
          <input aria-label="Actions" placeholder="account.contained client." value={rule.actions} onChange={(e) => setRule((r) => ({ ...r, actions: e.target.value }))} className={`${input} min-w-[12rem] flex-1`} />
          <input aria-label="Emails" placeholder="security@example.com" value={rule.emails} onChange={(e) => setRule((r) => ({ ...r, emails: e.target.value }))} className={`${input} min-w-[12rem] flex-1`} />
          <button type="submit" className="rounded-xl border border-[var(--hairline)] px-3 text-sm">Add alert</button>
        </form>
      </section>
    </AuthShell>
  );
}
