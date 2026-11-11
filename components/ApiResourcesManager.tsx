"use client";

import { FormEvent, useState } from "react";
import { AuthShell, Button, Label } from "@noirly-dev/ui";
import { AuthLogo } from "@/components/AuthLogo";
import { BusyOverlay, FormField, FormTextarea, Notice, SubmitButton, TextLink } from "@/components/auth-ui";
import { getCsrf } from "@/lib/auth/csrf-client";
import { formatGrantLines, formatScopeLines, parseGrantLines, parseScopeLines } from "@/lib/oauth/resource-form";

export type ApiResourceView = {
  identifier: string;
  name: string;
  scopes: Array<{ name: string; description: string }>;
  accessTokenTtlSeconds: number;
  allowedClientIds: string[];
  machineGrants: Array<{ clientId: string; scopes: string[] }>;
  status: "active" | "disabled";
};

type Props = { initialResources: ApiResourceView[]; clients: Array<{ clientId: string; name: string }> };

function emptyForm() {
  return { identifier: "", name: "", scopesText: "", ttl: "900", allowed: [] as string[], grantsText: "", status: "active" as "active" | "disabled" };
}

/** Registered APIs (RFC 8707 resources): their scopes, token lifetime, and which apps may ask. */
export function ApiResourcesManager({ initialResources, clients }: Props) {
  const [resources, setResources] = useState(initialResources);
  const [form, setForm] = useState(emptyForm());
  const [editing, setEditing] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const nameOf = (clientId: string) => clients.find((c) => c.clientId === clientId)?.name ?? clientId;

  function edit(resource: ApiResourceView) {
    setError(null);
    setNotice(null);
    setEditing(resource.identifier);
    setForm({
      identifier: resource.identifier,
      name: resource.name,
      scopesText: formatScopeLines(resource.scopes),
      ttl: String(resource.accessTokenTtlSeconds),
      allowed: resource.allowedClientIds,
      grantsText: formatGrantLines(resource.machineGrants),
      status: resource.status,
    });
  }

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = await fetch("/api/admin/resources", {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json", "x-csrf-token": await getCsrf() },
        body: JSON.stringify({
          identifier: form.identifier.trim(),
          name: form.name.trim(),
          scopes: parseScopeLines(form.scopesText),
          accessTokenTtlSeconds: Number(form.ttl),
          allowedClientIds: form.allowed,
          machineGrants: parseGrantLines(form.grantsText),
          status: form.status,
        }),
      });
      const data = (await res.json()) as { resource?: ApiResourceView; message?: string };
      if (!res.ok || !data.resource) {
        setError(data.message ?? "Could not save the API");
        return;
      }
      setResources((current) => [...current.filter((r) => r.identifier !== data.resource!.identifier), data.resource!].sort((a, b) => a.name.localeCompare(b.name)));
      setNotice(`${data.resource.name} saved.`);
      setEditing(null);
      setForm(emptyForm());
    } catch {
      setError("Could not save the API");
    } finally {
      setBusy(false);
    }
  }

  const toggleAllowed = (clientId: string) =>
    setForm((f) => ({ ...f, allowed: f.allowed.includes(clientId) ? f.allowed.filter((c) => c !== clientId) : [...f.allowed, clientId] }));

  return (
    <>
      {busy ? <BusyOverlay label="Saving API" /> : null}
      <AuthShell
        logo={<AuthLogo />}
        title="APIs"
        lead="APIs that accept Identity access tokens: their scopes, and which apps may ask for them."
        size="lg"
        align="top"
        className="py-8"
        footer={
          <div className="flex flex-wrap justify-center gap-4">
            <TextLink href="/clients">OAuth apps</TextLink>
            <TextLink href="/account">Back to account</TextLink>
          </div>
        }
      >
        <div className="mb-8 space-y-4">
          {resources.length === 0 ? (
            <p className="text-xs uppercase tracking-[0.12em] text-[var(--muted-foreground)]">No APIs yet</p>
          ) : (
            resources.map((resource) => (
              <article key={resource.identifier} data-api={resource.identifier} className="rounded-xl border border-[var(--hairline)] p-4">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <h2 className="font-display text-lg font-semibold tracking-tight">{resource.name}</h2>
                  <p className="text-[10px] uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
                    {resource.status} · tokens last {Math.round(resource.accessTokenTtlSeconds / 60)} min
                  </p>
                </div>
                <p className="mt-1 break-all font-mono text-[11px] text-[var(--muted-foreground)]">{resource.identifier}</p>
                {resource.scopes.length ? (
                  <ul aria-label={`Scopes of ${resource.name}`} className="mt-3 space-y-1 text-sm">
                    {resource.scopes.map((s) => (
                      <li key={s.name}><span className="font-mono text-xs">{s.name}</span>{s.description ? ` · ${s.description}` : ""}</li>
                    ))}
                  </ul>
                ) : null}
                <p className="mt-2 text-xs text-[var(--muted-foreground)]">
                  For people: {resource.allowedClientIds.length ? resource.allowedClientIds.map(nameOf).join(", ") : "no apps"}
                </p>
                <p className="text-xs text-[var(--muted-foreground)]">
                  As themselves: {resource.machineGrants.length ? resource.machineGrants.map((g) => `${nameOf(g.clientId)} (${g.scopes.join(" ") || "no scopes"})`).join(", ") : "no apps"}
                </p>
                <div className="mt-3">
                  <Button type="button" variant="ghost" size="sm" onClick={() => edit(resource)}>Edit <span className="sr-only">{resource.name}</span></Button>
                </div>
              </article>
            ))
          )}
        </div>

        <form className="flex flex-col gap-4 border-t border-[var(--hairline)] pt-8" onSubmit={(e) => void onSubmit(e)}>
          <h2 className="font-display text-xl font-semibold tracking-tight">{editing ? "Edit API" : "Register API"}</h2>
          <FormField label="Name" name="name" value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} placeholder="Ledger API" required />
          <FormField
            label="Identifier"
            name="identifier"
            value={form.identifier}
            onChange={(e) => setForm((f) => ({ ...f, identifier: e.target.value }))}
            placeholder="https://api.ledger.noirly.com"
            required
            readOnly={Boolean(editing)}
          />
          <FormTextarea
            label="Scopes"
            name="scopes"
            value={form.scopesText}
            onChange={(e) => setForm((f) => ({ ...f, scopesText: e.target.value }))}
            placeholder={"ledger.read: See your transactions\nledger.write: Add and change transactions"}
          />
          <FormField label="Token lifetime (seconds, 60–3600)" name="ttl" type="number" min={60} max={3600} value={form.ttl} onChange={(e) => setForm((f) => ({ ...f, ttl: e.target.value }))} />
          <fieldset className="flex flex-col gap-2">
            <legend className="mb-2 text-sm font-medium">Apps that may ask for it for people</legend>
            {clients.length === 0 ? <p className="text-xs text-[var(--muted-foreground)]">No apps registered yet.</p> : null}
            {clients.map((client) => (
              <label key={client.clientId} className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={form.allowed.includes(client.clientId)} onChange={() => toggleAllowed(client.clientId)} />
                {client.name} <span className="font-mono text-[11px] text-[var(--muted-foreground)]">{client.clientId}</span>
              </label>
            ))}
          </fieldset>
          <FormTextarea
            label="Apps that may call it as themselves"
            name="machineGrants"
            value={form.grantsText}
            onChange={(e) => setForm((f) => ({ ...f, grantsText: e.target.value }))}
            placeholder="ledger-sync: ledger.read ledger.write"
          />
          <div className="flex flex-col gap-2">
            <Label htmlFor="api-status">Status</Label>
            <select
              id="api-status"
              className="flex h-10 w-full rounded-xl border border-[var(--hairline)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--foreground)]"
              value={form.status}
              onChange={(e) => setForm((f) => ({ ...f, status: e.target.value as "active" | "disabled" }))}
            >
              <option value="active">Active</option>
              <option value="disabled">Disabled (no new tokens)</option>
            </select>
          </div>
          <p className="text-[10px] leading-relaxed text-[var(--muted-foreground)]">
            Scopes: one per line, with an optional description after a colon; people see the description when an app asks. Machine access: one app per line, its client ID, a colon, then the scopes it may have. Only confidential apps can use it.
          </p>
          {error ? <Notice tone="error">{error}</Notice> : null}
          {notice ? <Notice tone="success">{notice}</Notice> : null}
          <div className="flex gap-3">
            <SubmitButton busy={busy} busyLabel="Saving…">{editing ? "Save API" : "Register API"}</SubmitButton>
            {editing ? <Button type="button" variant="secondary" onClick={() => { setEditing(null); setForm(emptyForm()); }}>Cancel</Button> : null}
          </div>
        </form>
      </AuthShell>
    </>
  );
}
