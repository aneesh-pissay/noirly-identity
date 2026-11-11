"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import { getCsrf } from "@/lib/auth/csrf-client";

type Team = { id: string; name: string; parentId: string | null; memberIds: string[] };
type Member = { userId: string; displayName: string };

/** A space's teams, nested, with who's in each (admins with the members area manage them). */
export function SpaceTeams({ spaceId, members, canManage }: { spaceId: string; members: Member[]; canManage: boolean }) {
  const [teams, setTeams] = useState<Team[] | null>(null);
  const [name, setName] = useState("");
  const [parent, setParent] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const nameOf = useMemo(() => new Map(members.map((m) => [m.userId, m.displayName])), [members]);

  useEffect(() => {
    const controller = new AbortController();
    void fetch(`/api/spaces/${spaceId}/teams`, { credentials: "include", cache: "no-store", signal: controller.signal })
      .then(async (res) => (res.ok ? ((await res.json()) as { teams: Team[] }).teams : []))
      .then(setTeams)
      .catch(() => undefined);
    return () => controller.abort();
  }, [spaceId]);

  async function act(body: Record<string, unknown>, done: string) {
    setBusy(true);
    setMessage("");
    try {
      const res = await fetch(`/api/spaces/${spaceId}/teams`, {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json", "x-csrf-token": await getCsrf() },
        body: JSON.stringify(body),
      });
      const data = (await res.json()) as { teams?: Team[]; message?: string };
      if (!res.ok || !data.teams) throw new Error(data.message ?? "Something went wrong");
      setTeams(data.teams);
      setMessage(done);
    } catch (error) {
      setMessage((error as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (!teams || (!canManage && teams.length === 0)) return null;

  function branch(parentId: string | null, depth: number): React.ReactNode {
    const children = teams!.filter((t) => t.parentId === parentId);
    if (!children.length) return null;
    return (
      <ul className={depth ? "ml-4 border-l border-[var(--hairline)] pl-3" : ""}>
        {children.map((team) => (
          <li key={team.id} className="py-1 text-sm">
            <span className="font-medium">{team.name}</span>{" "}
            <span className="text-xs text-[var(--muted-foreground)]">
              {team.memberIds.length ? team.memberIds.map((id) => nameOf.get(id) ?? "someone").join(", ") : "nobody yet"}
            </span>
            {canManage ? (
              <span className="ml-2 inline-flex flex-wrap gap-2 text-xs">
                <select
                  aria-label={`Add someone to ${team.name}`}
                  value=""
                  disabled={busy}
                  onChange={(e) => e.target.value && void act({ action: "add-member", teamId: team.id, userId: e.target.value }, "Added.")}
                  className="rounded border border-[var(--hairline)] bg-transparent"
                >
                  <option value="">Add…</option>
                  {members.filter((m) => !team.memberIds.includes(m.userId)).map((m) => <option key={m.userId} value={m.userId}>{m.displayName}</option>)}
                </select>
                {team.memberIds.length ? (
                  <select
                    aria-label={`Remove someone from ${team.name}`}
                    value=""
                    disabled={busy}
                    onChange={(e) => e.target.value && void act({ action: "remove-member", teamId: team.id, userId: e.target.value }, "Removed.")}
                    className="rounded border border-[var(--hairline)] bg-transparent"
                  >
                    <option value="">Remove…</option>
                    {team.memberIds.map((id) => <option key={id} value={id}>{nameOf.get(id) ?? id}</option>)}
                  </select>
                ) : null}
                <button type="button" className="underline" disabled={busy} onClick={() => window.confirm(`Delete ${team.name}? Its sub-teams move up a level.`) && void act({ action: "delete", teamId: team.id }, "Deleted.")}>
                  Delete<span className="sr-only"> {team.name}</span>
                </button>
              </span>
            ) : null}
            {branch(team.id, depth + 1)}
          </li>
        ))}
      </ul>
    );
  }

  return (
    <section aria-labelledby={`teams-${spaceId}`} className="space-y-3 rounded-xl border border-[var(--hairline)] p-4">
      <h3 id={`teams-${spaceId}`} className="text-sm font-semibold">Teams</h3>
      <p className="text-xs text-[var(--muted-foreground)]">Groups inside the space. Someone in a sub-team counts as in the teams above it too.</p>
      {message ? <p role="status" className="text-xs">{message}</p> : null}
      {branch(null, 0)}
      {canManage ? (
        <form
          className="flex flex-wrap gap-2"
          onSubmit={(event: FormEvent) => {
            event.preventDefault();
            if (!name.trim()) return;
            void act({ action: "create", name: name.trim(), parentId: parent || null }, "Team created.").then(() => setName(""));
          }}
        >
          <label className="sr-only" htmlFor={`team-name-${spaceId}`}>Team name</label>
          <input id={`team-name-${spaceId}`} value={name} onChange={(e) => setName(e.target.value)} placeholder="Team name" className="h-9 min-w-[10rem] flex-1 rounded-xl border border-[var(--hairline)] bg-transparent px-3 text-sm" />
          <select aria-label="Inside" value={parent} onChange={(e) => setParent(e.target.value)} className="h-9 rounded-xl border border-[var(--hairline)] bg-transparent px-2 text-sm">
            <option value="">At the top</option>
            {teams.map((t) => <option key={t.id} value={t.id}>Inside {t.name}</option>)}
          </select>
          <button type="submit" disabled={busy || !name.trim()} className="rounded-xl border border-[var(--hairline)] px-3 text-sm disabled:opacity-50">Create team</button>
        </form>
      ) : null}
    </section>
  );
}
