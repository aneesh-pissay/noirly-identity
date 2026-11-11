"use client";

import { ChangeEvent, useEffect, useState } from "react";
import { getCsrf } from "@/lib/auth/csrf-client";

type Person = { userId: string; email: string; name: string; role: string };
type Directory = {
  deactivated: Array<{ userId: string; email: string | null; role: string; deactivatedAt: string; via: string; accountLocked: boolean }>;
  report: { domains: string[]; duplicates: Array<{ key: string; reason: string; accounts: Array<{ email: string; member: boolean }> }>; unmanaged: Person[]; outside: Person[] };
  scim: { tokens: Array<{ id: string; name: string; createdAt: string; lastUsedAt: string | null }>; adminGroups: string[] } | null;
};
type Row = { row: number; email?: string; ok: boolean; result: string };

const field = "w-full rounded-xl border border-[var(--hairline)] bg-transparent px-2 py-1.5 text-sm";
const button = "h-9 shrink-0 rounded-xl border border-[var(--hairline)] px-3 text-sm disabled:opacity-50";

async function post<T>(spaceId: string, body: unknown): Promise<T> {
  const res = await fetch(`/api/spaces/${spaceId}/directory`, { method: "POST", credentials: "include", headers: { "content-type": "application/json", "x-csrf-token": await getCsrf() }, body: JSON.stringify(body) });
  const data = (await res.json()) as T & { message?: string };
  if (!res.ok) throw new Error(data.message ?? "That didn't work");
  return data;
}

/** Directory: bulk invitation and CSV import, deactivated members, reconciliation and SCIM provisioning. */
export function SpaceDirectory({ spaceId }: { spaceId: string }) {
  const [dir, setDir] = useState<Directory | null>(null);
  const [emails, setEmails] = useState("");
  const [rows, setRows] = useState<Row[]>([]);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [tokenName, setTokenName] = useState("");
  const [newToken, setNewToken] = useState<string | null>(null);
  const [adminGroups, setAdminGroups] = useState("");

  async function load(signal?: AbortSignal) {
    const res = await fetch(`/api/spaces/${spaceId}/directory`, { credentials: "include", cache: "no-store", signal });
    if (!res.ok) return null;
    return (await res.json()) as Directory;
  }

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal).then((d) => { setDir(d); if (d?.scim) setAdminGroups(d.scim.adminGroups.join(", ")); }).catch(() => undefined);
    return () => controller.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [spaceId]);

  async function act(run: () => Promise<unknown>, done: string) {
    setBusy(true);
    setMessage("");
    try {
      await run();
      setMessage(done);
      setDir(await load());
    } catch (error) {
      setMessage((error as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function onCsv(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    const csv = await file.text();
    await act(async () => setRows((await post<{ results: Row[] }>(spaceId, { action: "import_csv", csv })).results), "Imported; see each row below.");
    event.target.value = "";
  }

  // Only admins with the members area see this (the API refuses others).
  if (!dir) return null;
  return (
    <section aria-labelledby={`directory-${spaceId}`} className="space-y-3 rounded-xl border border-[var(--hairline)] p-4 text-sm">
      <h3 id={`directory-${spaceId}`} className="text-sm font-semibold">Directory</h3>
      {message ? <p role="status" className="text-xs">{message}</p> : null}

      <div className="space-y-2">
        <label className="block text-xs font-medium" htmlFor={`bulk-${spaceId}`}>Invite several people (one address per line or comma)</label>
        <textarea id={`bulk-${spaceId}`} className={`${field} h-20`} value={emails} onChange={(e) => setEmails(e.target.value)} />
        <div className="flex flex-wrap gap-2">
          <button type="button" className={button} disabled={busy || !emails.trim()} onClick={() => void act(async () => setRows((await post<{ results: Row[] }>(spaceId, { action: "invite", emails: emails.split(/[\s,;]+/).filter(Boolean), role: "member" })).results), "Invitations sent; see each address below.")}>Invite as members</button>
          <label className={`${button} inline-flex cursor-pointer items-center`}>Import CSV<input type="file" accept=".csv,text/csv" className="sr-only" onChange={(e) => void onCsv(e)} /></label>
        </div>
        <p className="text-xs text-[var(--muted-foreground)]">CSV columns: <code>email</code>, and optionally <code>role</code> (member, admin, owner) and <code>teams</code> (names separated by <code>;</code>).</p>
        {rows.length ? <ul className="max-h-40 overflow-auto text-xs">{rows.map((r) => <li key={r.row}>{r.email ?? `Row ${r.row}`}: {r.ok ? "" : "✕ "}{r.result}</li>)}</ul> : null}
      </div>

      {dir.deactivated.length ? (
        <div className="space-y-1 border-t border-[var(--hairline)] pt-3">
          <p className="text-xs font-medium">Deactivated</p>
          <ul className="space-y-1">
            {dir.deactivated.map((d) => (
              <li key={d.userId} className="flex items-center justify-between gap-2 text-xs">
                <span>{d.email} ({d.role}{d.accountLocked ? ", account locked" : ""}), {new Date(d.deactivatedAt).toLocaleDateString()} by {d.via}</span>
                <button type="button" className="underline" disabled={busy} onClick={() => void act(() => post(spaceId, { action: "reactivate", userId: d.userId }), "Reactivated.")}>Reactivate</button>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {dir.report.duplicates.length || dir.report.outside.length ? (
        <div className="space-y-1 border-t border-[var(--hairline)] pt-3 text-xs">
          <p className="font-medium">Reconciliation</p>
          {dir.report.duplicates.map((d) => <p key={d.key}>Possible duplicate ({d.reason === "plus_alias" ? "same address but a +tag" : "an additional address of another account"}): {d.accounts.map((a) => `${a.email}${a.member ? " (member)" : ""}`).join(", ")}</p>)}
          {dir.report.outside.length ? <p>Members outside your domains (only their membership can be deactivated): {dir.report.outside.map((m) => m.email).join(", ")}</p> : null}
          {dir.scim && dir.report.unmanaged.length ? <p>Not managed by your directory yet: {dir.report.unmanaged.map((m) => m.email).join(", ")}</p> : null}
        </div>
      ) : null}

      {dir.scim ? (
        <div className="space-y-2 border-t border-[var(--hairline)] pt-3">
          <p className="text-xs font-medium">Provisioning (SCIM 2.0)</p>
          <p className="text-xs text-[var(--muted-foreground)]">Tenant URL: this site&apos;s address followed by <code>/api/scim/v2</code>. Give your directory a token below; guides are in PROVISIONING.md.</p>
          {newToken ? <p className="break-all rounded-lg border border-[var(--hairline)] p-2 text-xs">Copy it now, it won&apos;t be shown again: <code>{newToken}</code></p> : null}
          <ul className="space-y-1 text-xs">
            {dir.scim.tokens.map((t) => (
              <li key={t.id} className="flex items-center justify-between gap-2">
                <span>{t.name}{t.lastUsedAt ? `, last used ${new Date(t.lastUsedAt).toLocaleString()}` : ", not used yet"}</span>
                <button type="button" className="underline" disabled={busy} onClick={() => void act(() => post(spaceId, { action: "scim_revoke", tokenId: t.id }), "Token revoked.")}>Revoke</button>
              </li>
            ))}
          </ul>
          <div className="flex gap-2">
            <input className={field} placeholder="Connection name (e.g. Entra provisioning)" value={tokenName} onChange={(e) => setTokenName(e.target.value)} />
            <button type="button" className={button} disabled={busy || !tokenName.trim()} onClick={() => void act(async () => { setNewToken((await post<{ token: string }>(spaceId, { action: "scim_token", name: tokenName })).token); setTokenName(""); }, "Token created.")}>Create token</button>
          </div>
          <div className="flex gap-2">
            <input className={field} placeholder="Directory groups whose members are admins (comma-separated)" value={adminGroups} onChange={(e) => setAdminGroups(e.target.value)} />
            <button type="button" className={button} disabled={busy} onClick={() => void act(() => post(spaceId, { action: "scim_admin_groups", groups: adminGroups.split(",").map((g) => g.trim()).filter(Boolean) }), "Admin groups saved.")}>Save</button>
          </div>
        </div>
      ) : null}
    </section>
  );
}
