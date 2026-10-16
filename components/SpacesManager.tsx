"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { AuthShell, Button } from "@noirly-dev/ui";
import { AuthLogo } from "@/components/AuthLogo";
import { FormField, Notice, SubmitButton, TextLink } from "@/components/auth-ui";
import { getCsrf } from "@/lib/auth/csrf-client";
import type { SpaceDetail, SpaceRole, SpaceSummary } from "@/lib/spaces/space-service";

type Props = { userId: string; initialSpaces: SpaceSummary[] };

const ROLES: SpaceRole[] = ["member", "admin", "owner"];
const ROLE_LABEL: Record<SpaceRole, string> = { member: "Member", admin: "Admin", owner: "Owner" };

async function call<T>(path: string, method: string, body?: unknown): Promise<T> {
  const response = await fetch(path, {
    method,
    credentials: "include",
    headers: {
      ...(body !== undefined ? { "content-type": "application/json" } : {}),
      ...(method === "GET" ? {} : { "x-csrf-token": await getCsrf() }),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const data = (await response.json().catch(() => ({}))) as T & { message?: string };
  if (!response.ok) throw new Error(data.message ?? "Something went wrong");
  return data;
}

/**
 * Spaces: one team shared by every Noirly app. Teams in Flow (and later the
 * other apps) linked to a space follow its member list.
 */
export function SpacesManager({ userId, initialSpaces }: Props) {
  const [spaces, setSpaces] = useState(initialSpaces);
  const [selected, setSelected] = useState<(SpaceDetail & { role: SpaceRole }) | null>(null);
  const [newName, setNewName] = useState("");
  const [addEmail, setAddEmail] = useState("");
  const [addRole, setAddRole] = useState<SpaceRole>("member");
  const [rename, setRename] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const refreshList = useCallback(async () => {
    setSpaces((await call<{ spaces: SpaceSummary[] }>("/api/spaces", "GET")).spaces);
  }, []);

  const open = useCallback(async (spaceId: string) => {
    setError(null);
    const { space } = await call<{ space: SpaceDetail & { role: SpaceRole } }>(`/api/spaces/${spaceId}`, "GET");
    setSelected(space);
    setRename(space.name);
  }, []);

  useEffect(() => {
    if (!selected && spaces.length === 1) void open(spaces[0]!.id).catch(() => undefined);
  }, [spaces, selected, open]);

  async function run(action: () => Promise<void>, done?: string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await action();
      if (done) setNotice(done);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const canManage = selected ? selected.role !== "member" : false;
  const isOwner = selected?.role === "owner";

  return (
    <AuthShell
      logo={<AuthLogo />}
      title="Spaces"
      lead="A space is one team across every Noirly app. Link a Flow workspace to a space and it follows the space's members."
      size="lg"
      align="top"
      className="py-8"
      footer={
        <div className="flex flex-wrap items-center justify-center gap-4">
          <TextLink href="/account">Account</TextLink>
        </div>
      }
    >
      <div className="flex flex-col gap-6">
        {error ? <Notice tone="error">{error}</Notice> : null}
        {notice ? <Notice tone="success">{notice}</Notice> : null}

        <section className="flex flex-col gap-3">
          <h2 className="mono-label">Your spaces</h2>
          {spaces.length === 0 ? (
            <p className="text-sm text-[var(--muted-foreground)]">You're not in any space yet. Create one below.</p>
          ) : (
            <ul className="flex flex-col gap-1">
              {spaces.map((space) => (
                <li key={space.id}>
                  <button
                    type="button"
                    onClick={() => void run(() => open(space.id))}
                    aria-current={selected?.id === space.id ? "true" : undefined}
                    className={`flex w-full items-center justify-between rounded-xl border px-3 py-2 text-left text-sm transition-colors ${
                      selected?.id === space.id
                        ? "border-[var(--accent)] bg-[var(--accent-soft)]"
                        : "border-[var(--hairline)] hover:bg-[var(--surface-2)]"
                    }`}
                  >
                    <span className="font-medium">{space.name}</span>
                    <span className="text-xs text-[var(--muted-foreground)]">
                      {ROLE_LABEL[space.role]} · {space.memberCount} {space.memberCount === 1 ? "person" : "people"}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
          <form
            className="flex items-end gap-2"
            onSubmit={(event: FormEvent) => {
              event.preventDefault();
              if (!newName.trim()) return;
              void run(async () => {
                const { space } = await call<{ space: SpaceDetail }>("/api/spaces", "POST", { name: newName.trim() });
                setNewName("");
                await refreshList();
                await open(space.id);
              }, "Space created.");
            }}
          >
            <FormField
              label="New space"
              name="space-name"
              placeholder="e.g. Goa Trip, Flat 4B, Acme team"
              value={newName}
              maxLength={80}
              onChange={(event) => setNewName(event.target.value)}
              className="flex-1"
            />
            <SubmitButton busy={busy} disabled={!newName.trim()}>Create</SubmitButton>
          </form>
        </section>

        {selected ? (
          <section className="flex flex-col gap-4 border-t border-[var(--hairline)] pt-6">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <h2 className="text-lg font-semibold">{selected.name}</h2>
              <span className="text-xs text-[var(--muted-foreground)]">You are {ROLE_LABEL[selected.role].toLowerCase()}</span>
            </div>

            <ul className="flex flex-col divide-y divide-[var(--hairline)] rounded-xl border border-[var(--hairline)]">
              {selected.members.map((member) => {
                const me = member.userId === userId;
                const editable = canManage && !me && (member.role !== "owner" || isOwner);
                return (
                  <li key={member.userId} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
                    <span className="min-w-0">
                      <span className="block text-sm font-medium">{member.displayName}{me ? " (you)" : ""}</span>
                      <span className="block truncate text-xs text-[var(--muted-foreground)]">{member.email}</span>
                    </span>
                    <span className="flex items-center gap-2">
                      {editable ? (
                        <select
                          aria-label={`Role for ${member.displayName}`}
                          value={member.role}
                          disabled={busy}
                          onChange={(event) =>
                            void run(async () => {
                              const { space } = await call<{ space: SpaceDetail }>(
                                `/api/spaces/${selected.id}/members/${member.userId}`, "PATCH", { role: event.target.value },
                              );
                              setSelected({ ...space, role: selected.role });
                            }, "Role updated.")
                          }
                          className="h-8 rounded-lg border border-[var(--hairline)] bg-[var(--bg)] px-2 text-xs"
                        >
                          {ROLES.filter((role) => role !== "owner" || isOwner).map((role) => (
                            <option key={role} value={role}>{ROLE_LABEL[role]}</option>
                          ))}
                        </select>
                      ) : (
                        <span className="text-xs text-[var(--muted-foreground)]">{ROLE_LABEL[member.role]}</span>
                      )}
                      {editable ? (
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          disabled={busy}
                          onClick={() => {
                            if (!window.confirm(`Remove ${member.displayName} from ${selected.name}? They lose access in every linked app.`)) return;
                            void run(async () => {
                              await call(`/api/spaces/${selected.id}/members/${member.userId}`, "DELETE");
                              await open(selected.id);
                              await refreshList();
                            }, "Removed.");
                          }}
                        >
                          Remove
                        </Button>
                      ) : null}
                    </span>
                  </li>
                );
              })}
            </ul>

            {canManage ? (
              <form
                className="flex flex-wrap items-end gap-2"
                onSubmit={(event: FormEvent) => {
                  event.preventDefault();
                  if (!addEmail.trim()) return;
                  void run(async () => {
                    const { space } = await call<{ space: SpaceDetail }>(
                      `/api/spaces/${selected.id}/members`, "POST", { email: addEmail.trim(), role: addRole },
                    );
                    setSelected({ ...space, role: selected.role });
                    setAddEmail("");
                    await refreshList();
                  }, "Added. They now have access in every linked app.");
                }}
              >
                <FormField
                  label="Add someone by their Noirly email"
                  name="member-email"
                  type="email"
                  value={addEmail}
                  onChange={(event) => setAddEmail(event.target.value)}
                  className="min-w-[14rem] flex-1"
                />
                <select
                  aria-label="Role"
                  value={addRole}
                  onChange={(event) => setAddRole(event.target.value as SpaceRole)}
                  className="h-10 rounded-xl border border-[var(--hairline)] bg-[var(--bg)] px-2 text-sm"
                >
                  {ROLES.filter((role) => role !== "owner" || isOwner).map((role) => (
                    <option key={role} value={role}>{ROLE_LABEL[role]}</option>
                  ))}
                </select>
                <SubmitButton busy={busy} disabled={!addEmail.trim()}>Add</SubmitButton>
              </form>
            ) : null}

            {canManage ? (
              <form
                className="flex items-end gap-2"
                onSubmit={(event: FormEvent) => {
                  event.preventDefault();
                  void run(async () => {
                    const { space } = await call<{ space: SpaceDetail }>(`/api/spaces/${selected.id}`, "PATCH", { name: rename });
                    setSelected({ ...space, role: selected.role });
                    await refreshList();
                  }, "Renamed.");
                }}
              >
                <FormField
                  label="Name"
                  name="space-rename"
                  value={rename}
                  maxLength={80}
                  onChange={(event) => setRename(event.target.value)}
                  className="flex-1"
                />
                <SubmitButton busy={busy} disabled={!rename.trim() || rename.trim() === selected.name}>Rename</SubmitButton>
              </form>
            ) : null}

            <div className="flex flex-wrap gap-2">
              <Button
                type="button"
                variant="secondary"
                disabled={busy}
                onClick={() => {
                  if (!window.confirm(`Leave ${selected.name}? You lose access to its teams in every linked app.`)) return;
                  void run(async () => {
                    await call(`/api/spaces/${selected.id}/members/${userId}`, "DELETE");
                    setSelected(null);
                    await refreshList();
                  }, "You left the space.");
                }}
              >
                Leave space
              </Button>
              {isOwner ? (
                <Button
                  type="button"
                  variant="destructive"
                  disabled={busy}
                  onClick={() => {
                    if (!window.confirm(`Delete ${selected.name}? Linked teams are unlinked and kept as they are.`)) return;
                    void run(async () => {
                      await call(`/api/spaces/${selected.id}`, "DELETE");
                      setSelected(null);
                      await refreshList();
                    }, "Space deleted.");
                  }}
                >
                  Delete space
                </Button>
              ) : null}
            </div>
          </section>
        ) : null}
      </div>
    </AuthShell>
  );
}
