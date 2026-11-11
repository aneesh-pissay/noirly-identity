"use client";

import { useEffect, useState } from "react";
import { getCsrf } from "@/lib/auth/csrf-client";

type Rule = "everyone" | "admins" | "teams";
type View = {
  mode: "open" | "listed";
  apps: Array<{ appKey: string; name: string; access: Rule; teamIds: string[] }>;
  available: Array<{ appKey: string; name: string }>;
};

const RULE_LABEL: Record<Rule, string> = { everyone: "Everyone", admins: "Admins only", teams: "Chosen teams" };

/** Which apps the organization uses, and who may open each (admins with the apps area). */
export function SpaceApps({ spaceId, canManage }: { spaceId: string; canManage: boolean }) {
  const [view, setView] = useState<View | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    void fetch(`/api/spaces/${spaceId}/apps`, { credentials: "include", cache: "no-store", signal: controller.signal })
      .then(async (res) => (res.ok ? ((await res.json()) as View) : null))
      .then(setView)
      .catch(() => undefined);
    return () => controller.abort();
  }, [spaceId]);

  async function act(body: Record<string, unknown>, done: string) {
    setBusy(true);
    setMessage("");
    try {
      const res = await fetch(`/api/spaces/${spaceId}/apps`, {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json", "x-csrf-token": await getCsrf() },
        body: JSON.stringify(body),
      });
      const data = (await res.json()) as View & { message?: string };
      if (!res.ok) throw new Error(data.message ?? "Something went wrong");
      setView(data);
      setMessage(done);
    } catch (error) {
      setMessage((error as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function chooseRule(appKey: string, access: Rule) {
    let teamIds: string[] | undefined;
    if (access === "teams") {
      const answer = window.prompt("Which teams? Their ids, comma separated (from the Teams list)");
      if (!answer) return;
      teamIds = answer.split(/[\s,]+/).filter(Boolean);
    }
    await act({ action: "set", appKey, access, teamIds }, "Saved.");
  }

  if (!view) return null;
  const unlisted = view.available.filter((a) => !view.apps.some((x) => x.appKey === a.appKey));
  return (
    <section aria-labelledby={`apps-${spaceId}`} className="space-y-3 rounded-xl border border-[var(--hairline)] p-4">
      <h3 id={`apps-${spaceId}`} className="text-sm font-semibold">Apps</h3>
      <p className="text-xs text-[var(--muted-foreground)]">
        {view.mode === "open" ? "Any Noirly app can be opened in this space." : "Only the apps listed here can be opened in this space, by the people each allows."}
      </p>
      {message ? <p role="status" className="text-xs">{message}</p> : null}
      {canManage ? (
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={view.mode === "listed"}
            disabled={busy}
            onChange={(e) => void act({ action: "mode", mode: e.target.checked ? "listed" : "open" }, e.target.checked ? "Only listed apps now." : "Any app now.")}
          />
          Only allow the apps listed here
        </label>
      ) : null}
      <ul className="space-y-1">
        {view.apps.map((app) => (
          <li key={app.appKey} className="flex flex-wrap items-center gap-2 text-sm">
            <span className="font-medium">{app.name}</span>
            {canManage ? (
              <>
                <select aria-label={`Who may open ${app.name}`} value={app.access} disabled={busy} onChange={(e) => void chooseRule(app.appKey, e.target.value as Rule)} className="rounded border border-[var(--hairline)] bg-transparent text-xs">
                  {(Object.keys(RULE_LABEL) as Rule[]).map((rule) => <option key={rule} value={rule}>{RULE_LABEL[rule]}</option>)}
                </select>
                <button type="button" className="text-xs underline" disabled={busy} onClick={() => void act({ action: "remove", appKey: app.appKey }, `${app.name} removed.`)}>
                  Remove<span className="sr-only"> {app.name}</span>
                </button>
              </>
            ) : (
              <span className="text-xs text-[var(--muted-foreground)]">{RULE_LABEL[app.access]}</span>
            )}
          </li>
        ))}
      </ul>
      {canManage && unlisted.length ? (
        <select aria-label="Add an app" value="" disabled={busy} onChange={(e) => e.target.value && void act({ action: "set", appKey: e.target.value, access: "everyone" }, "App added.")} className="rounded-xl border border-[var(--hairline)] bg-transparent px-2 py-1 text-sm">
          <option value="">Add an app…</option>
          {unlisted.map((a) => <option key={a.appKey} value={a.appKey}>{a.name}</option>)}
        </select>
      ) : null}
    </section>
  );
}
