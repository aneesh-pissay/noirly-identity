"use client";

import { useEffect, useState } from "react";
import { getCsrf } from "@/lib/auth/csrf-client";
import { ABSOLUTE_CHOICES, IDLE_CHOICES } from "@/lib/sessions/lifetime-choices";

type Security = { requireMfa: boolean; allowedMethods: string[]; sessionPolicy: { idleSeconds: number | null; absoluteSeconds: number | null } };

const METHOD_LABEL: Record<string, string> = {
  password: "Password", passkey: "Passkey", magic_link: "Email link", email_code: "Email code", sso: "Single sign-on",
};

function duration(seconds: number) {
  if (seconds % 86_400 === 0) return `${seconds / 86_400} day${seconds === 86_400 ? "" : "s"}`;
  if (seconds % 3600 === 0) return `${seconds / 3600} hour${seconds === 3600 ? "" : "s"}`;
  return `${Math.round(seconds / 60)} minutes`;
}

/** The organization's sign-in methods and session limits (admins with the settings area). */
export function SpaceSecurity({ spaceId, canManage }: { spaceId: string; canManage: boolean }) {
  const [security, setSecurity] = useState<Security | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    void fetch(`/api/spaces/${spaceId}/security`, { credentials: "include", cache: "no-store", signal: controller.signal })
      .then(async (res) => (res.ok ? ((await res.json()) as Security) : null))
      .then(setSecurity)
      .catch(() => undefined);
    return () => controller.abort();
  }, [spaceId]);

  async function save(body: Partial<Security>, done: string) {
    setBusy(true);
    setMessage("");
    try {
      const res = await fetch(`/api/spaces/${spaceId}/security`, {
        method: "PATCH",
        credentials: "include",
        headers: { "content-type": "application/json", "x-csrf-token": await getCsrf() },
        body: JSON.stringify(body),
      });
      const data = (await res.json()) as Security & { message?: string };
      if (!res.ok) throw new Error(data.message ?? "Something went wrong");
      setSecurity(data);
      setMessage(done);
    } catch (error) {
      setMessage((error as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (!security) return null;
  const toggle = (method: string) => {
    const next = security.allowedMethods.includes(method) ? security.allowedMethods.filter((m) => m !== method) : [...security.allowedMethods, method];
    void save({ allowedMethods: next }, next.length ? "Saved." : "Any way of signing in is allowed again.");
  };
  return (
    <section aria-labelledby={`security-${spaceId}`} className="space-y-3 rounded-xl border border-[var(--hairline)] p-4">
      <h3 id={`security-${spaceId}`} className="text-sm font-semibold">Sign-in and sessions</h3>
      {message ? <p role="status" className="text-xs">{message}</p> : null}
      <fieldset className="space-y-1">
        <legend className="text-xs text-[var(--muted-foreground)]">
          Ways members may sign in to open apps here {security.allowedMethods.length ? "" : "(any, until you choose)"}
        </legend>
        <div className="flex flex-wrap gap-3">
          {Object.entries(METHOD_LABEL).map(([method, label]) => (
            <label key={method} className="flex items-center gap-1 text-sm">
              <input type="checkbox" disabled={!canManage || busy} checked={security.allowedMethods.includes(method)} onChange={() => toggle(method)} />
              {label}
            </label>
          ))}
        </div>
      </fieldset>
      <div className="flex flex-wrap gap-3 text-sm">
        <label className="flex items-center gap-1">
          Sign out after unused for
          <select
            disabled={!canManage || busy}
            value={security.sessionPolicy.idleSeconds ?? ""}
            onChange={(e) => void save({ sessionPolicy: { ...security.sessionPolicy, idleSeconds: e.target.value ? Number(e.target.value) : null } }, "Saved. Members' sessions follow it now.")}
            className="rounded border border-[var(--hairline)] bg-transparent"
          >
            {IDLE_CHOICES.map((s) => <option key={s ?? "none"} value={s ?? ""}>{s === null ? "No limit" : duration(s)}</option>)}
          </select>
        </label>
        <label className="flex items-center gap-1">
          Sessions last at most
          <select
            disabled={!canManage || busy}
            value={security.sessionPolicy.absoluteSeconds ?? ""}
            onChange={(e) => void save({ sessionPolicy: { ...security.sessionPolicy, absoluteSeconds: e.target.value ? Number(e.target.value) : null } }, "Saved. Members' sessions follow it now.")}
            className="rounded border border-[var(--hairline)] bg-transparent"
          >
            {ABSOLUTE_CHOICES.map((s) => <option key={s ?? "default"} value={s ?? ""}>{s === null ? "Identity's default" : duration(s)}</option>)}
          </select>
        </label>
      </div>
    </section>
  );
}
