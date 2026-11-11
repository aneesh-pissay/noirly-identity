"use client";

import { FormEvent, useEffect, useState } from "react";
import { getCsrf } from "@/lib/auth/csrf-client";

type Provider = {
  id: string;
  name: string;
  protocol: "oidc" | "saml";
  preset: "generic" | "entra" | "okta";
  enabled: boolean;
  domains: string[];
  jit: boolean;
  oidc: { issuer: string; clientId: string; hasSecret: boolean; redirectUri: string } | null;
  saml: { idpEntityId: string; ssoUrl: string; certificates: Array<{ fingerprint: string; notAfter: string }>; spEntityId: string; acsUrl: string; spMetadataUrl: string } | null;
  mapping: { groups: string; roles: Array<{ group: string; role: string }>; teams: Array<{ group: string; teamId: string }> };
  lastUsedAt: string | null;
};
type Enforcement = { enforced: boolean; breakGlass: Array<{ userId: string; email: string }> };
type State = { providers: Provider[]; enforcement: Enforcement };

const field = "h-9 w-full rounded-xl border border-[var(--hairline)] bg-transparent px-2 text-sm";

async function send(spaceId: string, body: unknown): Promise<State> {
  const res = await fetch(`/api/spaces/${spaceId}/sso`, { method: "POST", credentials: "include", headers: { "content-type": "application/json", "x-csrf-token": await getCsrf() }, body: JSON.stringify(body) });
  const data = (await res.json()) as State & { message?: string };
  if (!res.ok) throw new Error(data.message ?? "That didn't work");
  return data;
}

/** Single sign-on: the space's identity providers (Entra ID, Okta, any OIDC or SAML IdP), enforcement and break-glass accounts. */
export function SpaceSso({ spaceId, isOwner }: { spaceId: string; isOwner: boolean }) {
  const [state, setState] = useState<State | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({ name: "", protocol: "oidc", preset: "entra", domains: "", tenant: "", oktaDomain: "", issuer: "", clientId: "", clientSecret: "", metadataXml: "", idpEntityId: "", ssoUrl: "", certificate: "", groups: "", adminGroup: "" });
  const [breakGlass, setBreakGlass] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    void fetch(`/api/spaces/${spaceId}/sso`, { credentials: "include", cache: "no-store", signal: controller.signal })
      .then(async (res) => (res.ok ? ((await res.json()) as State) : null))
      .then((s) => { setState(s); if (s) setBreakGlass(s.enforcement.breakGlass.map((b) => b.email).join(", ")); })
      .catch(() => undefined);
    return () => controller.abort();
  }, [spaceId]);

  async function act(body: unknown, done: string) {
    setBusy(true);
    setMessage("");
    try {
      setState(await send(spaceId, body));
      setMessage(done);
    } catch (error) {
      setMessage((error as Error).message);
    } finally {
      setBusy(false);
    }
  }

  function add(event: FormEvent) {
    event.preventDefault();
    const domains = form.domains.split(/[\s,]+/).filter(Boolean);
    const mapping = form.groups || form.adminGroup ? { groups: form.groups, roles: form.adminGroup ? [{ group: form.adminGroup, role: "admin" }] : [] } : undefined;
    const provider =
      form.protocol === "oidc"
        ? { name: form.name, protocol: "oidc", preset: form.preset, domains, mapping, oidc: { tenant: form.tenant || undefined, oktaDomain: form.oktaDomain || undefined, issuer: form.issuer || undefined, clientId: form.clientId, clientSecret: form.clientSecret || undefined } }
        : { name: form.name, protocol: "saml", preset: form.preset, domains, mapping, saml: form.metadataXml ? { metadataXml: form.metadataXml } : { idpEntityId: form.idpEntityId, ssoUrl: form.ssoUrl, certificates: form.certificate ? [form.certificate] : undefined } };
    void act({ action: "save", provider }, "Identity provider saved.");
  }

  // Only those who manage domains see this section (the API refuses others).
  if (!state) return null;
  const set = (key: keyof typeof form) => (e: { target: { value: string } }) => setForm((f) => ({ ...f, [key]: e.target.value }));

  return (
    <section aria-labelledby={`sso-${spaceId}`} className="space-y-3 rounded-xl border border-[var(--hairline)] p-4">
      <h3 id={`sso-${spaceId}`} className="text-sm font-semibold">Single sign-on</h3>
      <p className="text-xs text-[var(--muted-foreground)]">People at your verified domains sign in through your own identity provider. Setup guides for Entra ID and Okta are in the docs (SSO.md).</p>
      {message ? <p role="status" className="text-xs">{message}</p> : null}

      <ul className="space-y-3 text-sm">
        {state.providers.map((p) => (
          <li key={p.id} className="space-y-1 rounded-lg border border-[var(--hairline)] p-3">
            <p className="font-medium">{p.name} <span className="text-xs text-[var(--muted-foreground)]">{p.protocol.toUpperCase()}{p.preset !== "generic" ? `, ${p.preset}` : ""}{p.enabled ? "" : ", off"}</span></p>
            <p className="text-xs">For {p.domains.join(", ")}{p.jit ? "; creates accounts on first sign-in" : ""}{p.lastUsedAt ? `; last used ${new Date(p.lastUsedAt).toLocaleDateString()}` : ""}</p>
            {p.oidc ? <p className="text-xs break-all">Redirect URI to register: <code>{p.oidc.redirectUri}</code></p> : null}
            {p.saml ? (
              <>
                <p className="text-xs break-all">Entity ID: <code>{p.saml.spEntityId}</code>; reply (ACS) URL: <code>{p.saml.acsUrl}</code> (<a className="underline" href={p.saml.spMetadataUrl}>metadata</a>)</p>
                <p className="text-xs">Certificates: {p.saml.certificates.map((c) => `expires ${new Date(c.notAfter).toLocaleDateString()}`).join(", ")}</p>
              </>
            ) : null}
            <div className="flex gap-2">
              <button type="button" disabled={busy} className="text-xs underline" onClick={() => void act({ action: "save", provider: { name: p.name, protocol: p.protocol, preset: p.preset, domains: p.domains, enabled: !p.enabled, ...(p.oidc ? { oidc: { issuer: p.oidc.issuer, clientId: p.oidc.clientId } } : { saml: {} }), id: p.id } }, p.enabled ? "Turned off." : "Turned on.")}>{p.enabled ? "Turn off" : "Turn on"}</button>
              <button type="button" disabled={busy} className="text-xs underline" onClick={() => void act({ action: "delete", id: p.id }, "Removed.")}>Remove</button>
            </div>
          </li>
        ))}
      </ul>

      <form onSubmit={add} className="grid gap-2 text-sm sm:grid-cols-2">
        <input className={field} placeholder="Name (e.g. Acme Entra ID)" value={form.name} onChange={set("name")} required />
        <input className={field} placeholder="Domains (verified), comma-separated" value={form.domains} onChange={set("domains")} required />
        <select className={field} value={form.protocol} onChange={set("protocol")}><option value="oidc">OpenID Connect</option><option value="saml">SAML 2.0</option></select>
        <select className={field} value={form.preset} onChange={set("preset")}><option value="entra">Microsoft Entra ID</option><option value="okta">Okta</option><option value="generic">Other</option></select>
        {form.protocol === "oidc" ? (
          <>
            {form.preset === "entra" ? <input className={field} placeholder="Entra tenant ID" value={form.tenant} onChange={set("tenant")} /> : form.preset === "okta" ? <input className={field} placeholder="Okta domain (example.okta.com)" value={form.oktaDomain} onChange={set("oktaDomain")} /> : <input className={field} placeholder="Issuer URL" value={form.issuer} onChange={set("issuer")} />}
            <input className={field} placeholder="Client ID" value={form.clientId} onChange={set("clientId")} required />
            <input className={field} type="password" placeholder="Client secret" value={form.clientSecret} onChange={set("clientSecret")} autoComplete="off" />
          </>
        ) : (
          <>
            <textarea className={`${field} h-20 sm:col-span-2`} placeholder="Paste the IdP's metadata XML (or fill the three fields below)" value={form.metadataXml} onChange={set("metadataXml")} />
            <input className={field} placeholder="IdP entity ID" value={form.idpEntityId} onChange={set("idpEntityId")} />
            <input className={field} placeholder="IdP sign-in URL" value={form.ssoUrl} onChange={set("ssoUrl")} />
            <textarea className={`${field} h-20 sm:col-span-2`} placeholder="IdP signing certificate (PEM)" value={form.certificate} onChange={set("certificate")} />
          </>
        )}
        <input className={field} placeholder="Groups claim (optional)" value={form.groups} onChange={set("groups")} />
        <input className={field} placeholder="Group whose members are space admins (optional)" value={form.adminGroup} onChange={set("adminGroup")} />
        <button type="submit" disabled={busy} className="h-9 rounded-xl border border-[var(--hairline)] px-3 text-sm sm:col-span-2">Add identity provider</button>
      </form>

      {isOwner && state.providers.length > 0 ? (
        <div className="space-y-2 border-t border-[var(--hairline)] pt-3 text-sm">
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={state.enforcement.enforced} disabled={busy} onChange={(e) => void act({ action: "enforcement", enforced: e.target.checked }, e.target.checked ? "Members at these domains now sign in only through your IdP." : "Enforcement off.")} />
            Require single sign-on for these domains
          </label>
          <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); void act({ action: "enforcement", breakGlassEmails: breakGlass.split(/[\s,]+/).filter(Boolean) }, "Break-glass accounts saved."); }}>
            <input className={field} placeholder="Break-glass accounts (up to 3 emails, with a second step)" value={breakGlass} onChange={(e) => setBreakGlass(e.target.value)} />
            <button type="submit" disabled={busy} className="h-9 shrink-0 rounded-xl border border-[var(--hairline)] px-3 text-sm">Save</button>
          </form>
          <p className="text-xs text-[var(--muted-foreground)]">If your IdP is down, these accounts sign in at /login?break_glass=1 with their password and second step. Every use is recorded and emailed to owners.</p>
        </div>
      ) : null}
    </section>
  );
}
