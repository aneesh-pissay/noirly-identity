"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import { AuthShell, Button, Label } from "@noirly-dev/ui";
import { AuthLogo } from "@/components/AuthLogo";
import {
  BusyOverlay,
  FormField,
  FormTextarea,
  Notice,
  SubmitButton,
  TextLink,
} from "@/components/auth-ui";
import { getCsrf } from "@/lib/auth/csrf-client";
import { slugifyClientId, urisFromOrigins } from "@/lib/oauth/app-origins";
import type { ClientType, PublicOAuthClient } from "@/types";
import { APP_ENVIRONMENTS, ENVIRONMENT_LABEL, type AppEnvironment } from "@/lib/oauth/environments";

type Props = {
  issuer: string;
  initialClients: PublicOAuthClient[];
  /** Admins register and delete apps; owners manage only their own. */
  isAdmin?: boolean;
  /** Owner user ids to emails, for the apps shown. */
  initialOwners?: Record<string, string>;
};

type MutateResponse = {
  client?: PublicOAuthClient;
  clientSecret?: string | null;
  created?: boolean;
  deleted?: boolean;
  message?: string;
};

type BusyState = "register" | "update" | "rotate" | "disable" | "delete" | null;

function parseLines(value: string): string[] {
  return value
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function envSnippet(issuer: string, clientId: string, secret: string): string {
  return [
    `AUTH_NOIRLY_ISSUER=${issuer}`,
    `AUTH_NOIRLY_CLIENT_ID=${clientId}`,
    `AUTH_NOIRLY_CLIENT_SECRET=${secret}`,
  ].join("\n");
}

function emptyForm() {
  return {
    name: "",
    clientId: "",
    clientIdTouched: false,
    clientType: "confidential" as ClientType,
    originsText: "",
    redirectUrisText: "",
    sha1Text: "",
    environment: "" as "" | AppEnvironment,
    backchannelLogoutUri: "",
    frontchannelLogoutUri: "",
  };
}

export function ClientGenerator({ issuer, initialClients, isAdmin = true, initialOwners = {} }: Props) {
  const [csrf, setCsrf] = useState("");
  const [clients, setClients] = useState(initialClients);
  const [owners, setOwners] = useState(initialOwners);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState(emptyForm);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [issued, setIssued] = useState<{ clientId: string; secret: string } | null>(
    null,
  );
  const [busy, setBusy] = useState<BusyState>(null);

  useEffect(() => {
    void getCsrf().then(setCsrf);
  }, []);

  const derivedId = slugifyClientId(form.name);
  const effectiveId =
    (form.clientIdTouched ? form.clientId : derivedId) || form.clientId;
  const preview = useMemo(() => {
    try {
      const origins = parseLines(form.originsText);
      if (!origins.length) return null;
      return urisFromOrigins(origins);
    } catch {
      return null;
    }
  }, [form.originsText]);

  async function adminFetch(url: string, init: RequestInit) {
    return fetch(url, {
      ...init,
      credentials: "include",
      headers: {
        "content-type": "application/json",
        "x-csrf-token": csrf || (await getCsrf()),
        ...(init.headers ?? {}),
      },
    });
  }

  function resetForm() {
    setEditingId(null);
    setForm(emptyForm());
    setIssued(null);
  }

  function beginEdit(client: PublicOAuthClient) {
    setError(null);
    setNotice(null);
    setIssued(null);
    setEditingId(client.clientId);
    setForm({
      name: client.name,
      clientId: client.clientId,
      clientIdTouched: true,
      clientType: client.clientType,
      originsText: "",
      redirectUrisText: client.redirectUris.join("\n"),
      sha1Text: (client.androidSha1Fingerprints ?? []).join("\n"),
      // An older client's environment is only a guess: leave it unset until chosen.
      environment: client.environmentSet ? client.environment : "",
      backchannelLogoutUri: client.backchannelLogoutUri ?? "",
      frontchannelLogoutUri: client.frontchannelLogoutUri ?? "",
    });
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setNotice(null);
    setIssued(null);

    if (editingId) {
      setBusy("update");
      try {
        const redirectUris = parseLines(form.redirectUrisText);
        const origins = parseLines(form.originsText);
        const res = await adminFetch(
          `/api/admin/clients/${encodeURIComponent(editingId)}`,
          {
            method: "PATCH",
            body: JSON.stringify({
              name: form.name.trim(),
              clientType: form.clientType,
              ...(redirectUris.length
                ? { redirectUris, replaceUris: true }
                : origins.length
                  ? { origins, replaceUris: true }
                  : {}),
              androidSha1Fingerprints: parseLines(form.sha1Text),
              ...(form.environment ? { environment: form.environment } : {}),
              backchannelLogoutUri: form.backchannelLogoutUri.trim() || null,
              frontchannelLogoutUri: form.frontchannelLogoutUri.trim() || null,
            }),
          },
        );
        const data = (await res.json()) as MutateResponse;
        if (!res.ok || !data.client) {
          setError(data.message ?? "Could not update client");
          return;
        }
        setClients((current) =>
          current
            .map((item) =>
              item.clientId === data.client!.clientId ? data.client! : item,
            )
            .sort((a, b) => a.name.localeCompare(b.name)),
        );
        if (data.clientSecret) {
          setIssued({ clientId: data.client.clientId, secret: data.clientSecret });
          setNotice(
            "Client updated. A new secret was issued — copy it now; it will not be shown again.",
          );
        } else {
          setNotice(`${data.client.clientId} updated.`);
        }
        setEditingId(null);
        setForm(emptyForm());
      } catch {
        setError("Could not update client");
      } finally {
        setBusy(null);
      }
      return;
    }

    setBusy("register");
    try {
      const origins = parseLines(form.originsText);
      const redirectUris = parseLines(form.redirectUrisText);
      const res = await adminFetch("/api/admin/clients", {
        method: "POST",
        body: JSON.stringify({
          name: form.name.trim(),
          clientId: effectiveId.trim(),
          clientType: form.clientType,
          origins: origins.length ? origins : undefined,
          redirectUris: redirectUris.length ? redirectUris : undefined,
          androidSha1Fingerprints: parseLines(form.sha1Text),
              ...(form.environment ? { environment: form.environment } : {}),
        }),
      });
      const data = (await res.json()) as MutateResponse;
      if (!res.ok || !data.client) {
        setError(data.message ?? "Could not register client");
        return;
      }
      setClients((current) => {
        const next = current.filter(
          (item) => item.clientId !== data.client!.clientId,
        );
        return [...next, data.client!].sort((a, b) => a.name.localeCompare(b.name));
      });
      if (data.clientSecret) {
        setIssued({ clientId: data.client.clientId, secret: data.clientSecret });
        setNotice(
          data.created
            ? "Client created. Copy the secret now — it will not be shown again."
            : "Secret rotated.",
        );
      } else {
        setNotice(
          data.created
            ? "Public client created (no secret)."
            : "Client already existed. New URIs were added. Secret was not changed.",
        );
      }
      setForm(emptyForm());
    } catch {
      setError("Could not register client");
    } finally {
      setBusy(null);
    }
  }

  /**
   * "planned": the old secret keeps working for a day while the app switches.
   * "leaked": the old secret stops at once, and the app's own tokens are revoked.
   * "retire": the old secret (from a planned rotation) stops now.
   */
  async function onRotate(targetId: string, mode: "planned" | "leaked" | "retire" = "planned") {
    const question =
      mode === "planned"
        ? `Rotate the secret for ${targetId}? The old one keeps working for 24 hours, so you can update AUTH_NOIRLY_CLIENT_SECRET without downtime.`
        : mode === "leaked"
          ? `Replace the secret for ${targetId} now? The old one stops working at once, and the app's own tokens are revoked. The app can't sign anyone in until it has the new secret.`
          : `Stop accepting the old secret for ${targetId} now?`;
    if (!window.confirm(question)) {
      return;
    }
    setError(null);
    setNotice(null);
    setBusy("rotate");
    try {
      const body =
        mode === "planned"
          ? { rotateSecret: true, secretOverlapSeconds: 86_400 }
          : mode === "leaked"
            ? { rotateSecret: true, secretOverlapSeconds: 0, revokeMachineTokens: true }
            : { dropPreviousSecret: true };
      const res = await adminFetch(`/api/admin/clients/${encodeURIComponent(targetId)}`, {
        method: "PATCH",
        body: JSON.stringify(body),
      });
      const data = (await res.json()) as MutateResponse;
      if (!res.ok || !data.client || (mode !== "retire" && !data.clientSecret)) {
        setError(data.message ?? "Could not change the secret");
        return;
      }
      setClients((current) =>
        current.map((item) =>
          item.clientId === data.client!.clientId ? data.client! : item,
        ),
      );
      if (data.clientSecret) setIssued({ clientId: data.client.clientId, secret: data.clientSecret });
      setNotice(
        mode === "planned"
          ? "Secret rotated. Copy it now: it won't be shown again. The old one works for another 24 hours."
          : mode === "leaked"
            ? "Secret replaced. Copy it now: it won't be shown again. The old one no longer works."
            : "The old secret no longer works.",
      );
    } catch {
      setError("Could not change the secret");
    } finally {
      setBusy(null);
    }
  }

  /** A development, staging or production copy of an app, with its own ID, secret and redirects. */
  async function onAddEnvironment(client: PublicOAuthClient) {
    const missing = APP_ENVIRONMENTS.filter((env) => !clients.some((c) => c.appKey === client.appKey && c.environment === env));
    const environment = window.prompt(`Which environment of ${client.name}? (${missing.join(", ")})`, missing[0])?.trim() as AppEnvironment | undefined;
    if (!environment) return;
    if (!missing.includes(environment)) {
      setError(`Choose one of: ${missing.join(", ")}`);
      return;
    }
    const origins = window.prompt(`Its origins, comma separated (${environment === "development" ? "such as http://localhost:3001" : "https only"})`)?.trim();
    if (!origins) return;
    setError(null);
    setNotice(null);
    setIssued(null);
    setBusy("register");
    try {
      const res = await adminFetch(`/api/admin/clients/${encodeURIComponent(client.clientId)}/environments`, {
        method: "POST",
        body: JSON.stringify({ environment, origins: parseLines(origins) }),
      });
      const data = (await res.json()) as MutateResponse;
      if (!res.ok || !data.client) {
        setError(data.message ?? "Could not add the environment");
        return;
      }
      setClients((current) => [...current, data.client!].sort((a, b) => a.name.localeCompare(b.name) || APP_ENVIRONMENTS.indexOf(a.environment) - APP_ENVIRONMENTS.indexOf(b.environment)));
      if (data.clientSecret) setIssued({ clientId: data.client.clientId, secret: data.clientSecret });
      setNotice(`${ENVIRONMENT_LABEL[environment]} added as ${data.client.clientId}.${data.clientSecret ? " Copy its secret now: it won't be shown again." : ""}`);
    } catch {
      setError("Could not add the environment");
    } finally {
      setBusy(null);
    }
  }

  /** Who manages the app besides admins, by email (every environment of it). */
  async function onOwners(client: PublicOAuthClient) {
    const current = client.ownerIds.map((id) => owners[id] ?? id).join(", ");
    const answer = window.prompt(`Owners of ${client.name}: emails of verified Noirly accounts, comma separated (empty for admins only)`, current);
    if (answer === null) return;
    setError(null);
    setNotice(null);
    setBusy("update");
    try {
      const res = await adminFetch(`/api/admin/clients/${encodeURIComponent(client.clientId)}`, {
        method: "PATCH",
        body: JSON.stringify({ owners: parseLines(answer) }),
      });
      const data = (await res.json()) as MutateResponse & { owners?: Array<{ userId: string; email: string }> };
      if (!res.ok || !data.client) {
        setError(data.message ?? "Could not change the owners");
        return;
      }
      const list = await (await fetch("/api/admin/clients", { credentials: "include", cache: "no-store" })).json() as { clients?: PublicOAuthClient[]; owners?: Record<string, string> };
      if (list.clients) setClients(list.clients);
      if (list.owners) setOwners(list.owners);
      setNotice(`Owners of ${client.name} updated.`);
    } catch {
      setError("Could not change the owners");
    } finally {
      setBusy(null);
    }
  }

  /** Who may use the app: anyone, members of chosen spaces (by slug), or listed people (by email). */
  async function onAccess(client: PublicOAuthClient) {
    const mode = window.prompt(`Who may use ${client.name}? Type anyone, spaces or allowlist`, client.accessMode)?.trim().toLowerCase();
    if (!mode) return;
    if (!["anyone", "spaces", "allowlist"].includes(mode)) {
      setError("Type anyone, spaces or allowlist");
      return;
    }
    let extra: Record<string, string[]> = {};
    if (mode === "spaces") {
      const slugs = window.prompt("Which spaces? Their slugs, comma separated");
      if (!slugs) return;
      extra = { spaces: parseLines(slugs) };
    } else if (mode === "allowlist") {
      const emails = window.prompt("Who? Emails of verified Noirly accounts, comma separated");
      if (!emails) return;
      extra = { emails: parseLines(emails) };
    }
    setError(null);
    setNotice(null);
    setBusy("update");
    try {
      const res = await adminFetch(`/api/admin/clients/${encodeURIComponent(client.clientId)}`, {
        method: "PATCH",
        body: JSON.stringify({ accessPolicy: { mode, ...extra } }),
      });
      const data = (await res.json()) as MutateResponse;
      if (!res.ok || !data.client) {
        setError(data.message ?? "Could not change who may use it");
        return;
      }
      setClients((current) => current.map((item) => (item.clientId === data.client!.clientId ? data.client! : item)));
      setNotice(`Access to ${client.name} updated.`);
    } catch {
      setError("Could not change who may use it");
    } finally {
      setBusy(null);
    }
  }

  async function onToggleStatus(client: PublicOAuthClient) {
    const nextStatus = client.status === "active" ? "disabled" : "active";
    setError(null);
    setBusy("disable");
    try {
      const res = await adminFetch(
        `/api/admin/clients/${encodeURIComponent(client.clientId)}`,
        {
          method: "PATCH",
          body: JSON.stringify({ status: nextStatus }),
        },
      );
      const data = (await res.json()) as MutateResponse;
      if (!res.ok || !data.client) {
        setError(data.message ?? "Could not update client");
        return;
      }
      setClients((current) =>
        current.map((item) =>
          item.clientId === data.client!.clientId ? data.client! : item,
        ),
      );
      setNotice(
        nextStatus === "disabled"
          ? `${client.clientId} is disabled.`
          : `${client.clientId} is active.`,
      );
    } catch {
      setError("Could not update client");
    } finally {
      setBusy(null);
    }
  }

  async function onDelete(client: PublicOAuthClient) {
    if (
      !window.confirm(
        `Delete OAuth client ${client.clientId}? Apps using it will stop authenticating.`,
      )
    ) {
      return;
    }
    setError(null);
    setBusy("delete");
    try {
      const res = await adminFetch(
        `/api/admin/clients/${encodeURIComponent(client.clientId)}`,
        { method: "DELETE" },
      );
      const data = (await res.json()) as MutateResponse;
      if (!res.ok || !data.deleted) {
        setError(data.message ?? "Could not delete client");
        return;
      }
      setClients((current) =>
        current.filter((item) => item.clientId !== client.clientId),
      );
      if (editingId === client.clientId) {
        resetForm();
      }
      setNotice(`${client.clientId} deleted.`);
    } catch {
      setError("Could not delete client");
    } finally {
      setBusy(null);
    }
  }

  async function copySnippet() {
    if (!issued) return;
    try {
      await navigator.clipboard.writeText(
        envSnippet(issuer, issued.clientId, issued.secret),
      );
      setNotice("Copied env values to clipboard.");
    } catch {
      setError("Could not copy to clipboard");
    }
  }

  const busyLabel =
    busy === "rotate"
      ? "Rotating secret"
      : busy === "disable"
        ? "Updating client"
        : busy === "update"
          ? "Saving client"
          : busy === "delete"
            ? "Deleting client"
            : "Registering client";

  return (
    <>
      {busy ? <BusyOverlay label={busyLabel} /> : null}
      <AuthShell
        logo={<AuthLogo />}
        title="OAuth apps"
        lead="Register Flow, Ledger, Pulse, or any future Noirly app."
        size="lg"
        align="top"
        className="py-8"
        footer={
          <div className="flex flex-wrap justify-center gap-4">
            <TextLink href="/apis">APIs</TextLink>
            <TextLink href="/account">Back to account</TextLink>
          </div>
        }
      >
        <div className="mb-8 space-y-4">
          {clients.length === 0 ? (
            <p className="text-xs uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
              No clients yet
            </p>
          ) : (
            clients.map((client) => (
              <article
                key={client.clientId}
                className={`rounded-xl border p-4 ${
                  editingId === client.clientId
                    ? "border-[var(--accent)]"
                    : "border-[var(--hairline)]"
                }`}
              >
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <h2 className="font-display text-lg font-semibold tracking-tight">
                    {client.name}
                  </h2>
                  <p className="text-[10px] uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
                    {ENVIRONMENT_LABEL[client.environment]}{client.environmentSet ? "" : " (not set)"} · {client.clientType} · {client.status}
                  </p>
                </div>
                <p className="mt-1 font-mono text-[11px] text-[var(--muted-foreground)]">
                  {client.clientId}
                </p>
                <ul className="mt-3 space-y-1 break-all font-mono text-[11px] text-[var(--muted-foreground)]">
                  {client.redirectUris.map((uri) => (
                    <li key={uri}>{uri}</li>
                  ))}
                </ul>
                {client.androidSha1Fingerprints?.length ? (
                  <ul className="mt-2 space-y-1 break-all font-mono text-[11px] text-[var(--muted-foreground)]">
                    {client.androidSha1Fingerprints.map((fp) => (
                      <li key={fp}>SHA-1 {fp}</li>
                    ))}
                  </ul>
                ) : null}
                <p className="mt-2 text-xs text-[var(--muted-foreground)]">
                  Who can use it: {client.accessMode === "anyone" ? "anyone with a Noirly account" : client.accessMode === "spaces" ? "members of chosen spaces" : "listed people only"}
                </p>
                <p className="text-xs text-[var(--muted-foreground)]">
                  Owners: {client.ownerIds.length ? client.ownerIds.map((id) => owners[id] ?? id).join(", ") : "admins only"}
                </p>
                {client.previousSecretExpiresAt ? (
                  <p className="mt-2 text-xs text-[var(--muted-foreground)]">
                    The old secret works until {new Date(client.previousSecretExpiresAt).toLocaleString()}
                    {client.previousSecretLastUsedAt
                      ? `; last used ${new Date(client.previousSecretLastUsedAt).toLocaleString()}`
                      : "; not used since the rotation"}
                    .
                  </p>
                ) : null}
                <div className="mt-3 flex flex-wrap gap-2">
                  <Button type="button" variant="ghost" size="sm" onClick={() => beginEdit(client)}>
                    Edit
                  </Button>
                  {client.clientType === "confidential" ? (
                    <>
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        onClick={() => void onRotate(client.clientId)}
                      >
                        Rotate secret
                      </Button>
                      {client.previousSecretExpiresAt ? (
                        <Button type="button" variant="ghost" size="sm" onClick={() => void onRotate(client.clientId, "retire")}>
                          Retire old secret
                        </Button>
                      ) : null}
                      <Button type="button" variant="ghost" size="sm" onClick={() => void onRotate(client.clientId, "leaked")}>
                        Secret leaked
                      </Button>
                    </>
                  ) : null}
                  {APP_ENVIRONMENTS.some((env) => !clients.some((c) => c.appKey === client.appKey && c.environment === env)) ? (
                    <Button type="button" variant="ghost" size="sm" onClick={() => void onAddEnvironment(client)}>
                      Add environment
                    </Button>
                  ) : null}
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    onClick={() => void onToggleStatus(client)}
                  >
                    {client.status === "active" ? "Disable" : "Enable"}
                  </Button>
                  <Button type="button" variant="ghost" size="sm" onClick={() => void onOwners(client)}>
                    Owners
                  </Button>
                  <Button type="button" variant="ghost" size="sm" onClick={() => void onAccess(client)}>
                    Who can use it
                  </Button>
                  {isAdmin ? (
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => void onDelete(client)}
                    >
                      Delete
                    </Button>
                  ) : null}
                </div>
              </article>
            ))
          )}
        </div>

        {isAdmin || editingId ? <form className="flex flex-col gap-4 border-t border-[var(--hairline)] pt-8" onSubmit={onSubmit}>
          <div>
            <p className="text-xs font-medium uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
              {editingId ? "Editor" : "Generator"}
            </p>
            <h2 className="mt-2 font-display text-xl font-semibold tracking-tight">
              {editingId ? "Edit app" : "Register app"}
            </h2>
          </div>
          <FormField
            label="App name"
            name="name"
            value={form.name}
            onChange={(event) =>
              setForm((current) => ({ ...current, name: event.target.value }))
            }
            placeholder="Noirly Ledger"
            required
          />
          <FormField
            label="Client ID"
            name="clientId"
            value={
              editingId
                ? form.clientId
                : form.clientIdTouched
                  ? form.clientId
                  : derivedId
            }
            onChange={(event) => {
              if (editingId) return;
              setForm((current) => ({
                ...current,
                clientIdTouched: true,
                clientId: event.target.value,
              }));
            }}
            placeholder="noirly-ledger"
            required
            readOnly={Boolean(editingId)}
          />
          <div className="flex flex-col gap-2">
            <Label htmlFor="client-type">Client type</Label>
            <select
              id="client-type"
              className="flex h-10 w-full rounded-xl border border-[var(--hairline)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--foreground)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)]"
              value={form.clientType}
              onChange={(event) =>
                setForm((current) => ({
                  ...current,
                  clientType: event.target.value as ClientType,
                }))
              }
            >
              <option value="confidential">Confidential (web)</option>
              <option value="public">Public (native mobile)</option>
            </select>
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="client-environment">Environment</Label>
            <select
              id="client-environment"
              className="flex h-10 w-full rounded-xl border border-[var(--hairline)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--foreground)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)]"
              value={form.environment}
              onChange={(event) =>
                setForm((current) => ({ ...current, environment: event.target.value as "" | AppEnvironment }))
              }
            >
              <option value="">Not set (no redirect rules; shown as the redirects suggest)</option>
              {APP_ENVIRONMENTS.map((env) => (
                <option key={env} value={env}>{ENVIRONMENT_LABEL[env]}</option>
              ))}
            </select>
            <p className="text-[10px] leading-relaxed text-[var(--muted-foreground)]">
              Production and staging redirect only to https on real hosts; development only to localhost. Each environment is its own client, with its own ID and secret: use Add environment on an app.
            </p>
          </div>
          <FormTextarea
            label="App origins"
            name="origins"
            value={form.originsText}
            onChange={(event) =>
              setForm((current) => ({
                ...current,
                originsText: event.target.value,
              }))
            }
            placeholder={`http://localhost:3003\nhttps://noirly.ledger.aneesh-pissay.in`}
          />
          <FormTextarea
            label="Redirect URIs"
            name="redirectUris"
            value={form.redirectUrisText}
            onChange={(event) =>
              setForm((current) => ({
                ...current,
                redirectUrisText: event.target.value,
              }))
            }
            placeholder={`noirlyflow://oauth\nor leave blank to derive from origins`}
          />
          <FormTextarea
            label="Android SHA-1"
            name="androidSha1"
            value={form.sha1Text}
            onChange={(event) =>
              setForm((current) => ({
                ...current,
                sha1Text: event.target.value,
              }))
            }
            placeholder={`AA:BB:CC:DD:… (debug / release signing cert)\nOne fingerprint per line`}
          />
          {editingId ? (
            <>
              <FormField
                label="Back-channel logout URI"
                name="backchannelLogoutUri"
                value={form.backchannelLogoutUri}
                onChange={(event) =>
                  setForm((current) => ({ ...current, backchannelLogoutUri: event.target.value }))
                }
                placeholder="https://app.example.com/api/auth/backchannel-logout"
              />
              <FormField
                label="Front-channel logout URI"
                name="frontchannelLogoutUri"
                value={form.frontchannelLogoutUri}
                onChange={(event) =>
                  setForm((current) => ({ ...current, frontchannelLogoutUri: event.target.value }))
                }
                placeholder="https://app.example.com/auth/frontchannel-logout"
              />
              <p className="text-[10px] leading-relaxed text-[var(--muted-foreground)]">
                When an Identity session ends, Identity POSTs a logout token to the back-channel URI.
                The front-channel URI is loaded in a hidden frame when someone signs out in the browser,
                for apps without a back-channel or when it fails. Leave blank for none.
              </p>
            </>
          ) : null}
          <p className="text-[10px] leading-relaxed text-[var(--muted-foreground)]">
            Web apps: paste origins. Native apps: paste redirect URIs (e.g.
            noirlyflow://oauth) and optional Android SHA-1 fingerprints.
            {editingId
              ? " Saving replaces redirect URIs and SHA-1s with the values below."
              : null}
          </p>
          {preview && !editingId ? (
            <div className="font-mono text-[11px] leading-relaxed text-[var(--muted-foreground)]">
              <p className="uppercase tracking-[0.12em]">Callbacks</p>
              <ul className="mt-2 space-y-1 break-all">
                {preview.redirectUris.map((uri) => (
                  <li key={uri}>{uri}</li>
                ))}
              </ul>
            </div>
          ) : null}
          {error ? <Notice tone="error">{error}</Notice> : null}
          {notice ? <Notice tone="success">{notice}</Notice> : null}
          {issued ? (
            <div className="rounded-xl border border-[var(--hairline)] p-3">
              <p className="text-[11px] uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
                Paste into the app env
              </p>
              <pre className="mt-2 overflow-x-auto whitespace-pre-wrap font-mono text-[11px] leading-relaxed">
                {envSnippet(issuer, issued.clientId, issued.secret)}
              </pre>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="mt-3"
                onClick={() => void copySnippet()}
              >
                Copy
              </Button>
            </div>
          ) : null}
          <div className="flex flex-wrap gap-3">
            <SubmitButton
              busy={busy === "register" || busy === "update"}
              busyLabel={editingId ? "Saving" : "Registering"}
            >
              {editingId ? "Save changes" : "Generate client"}
            </SubmitButton>
            {editingId ? (
              <Button
                type="button"
                variant="secondary"
                onClick={() => {
                  resetForm();
                  setError(null);
                  setNotice(null);
                }}
              >
                Cancel
              </Button>
            ) : null}
          </div>
        </form> : null}
      </AuthShell>
    </>
  );
}
