"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { getCsrf } from "@/lib/auth/csrf-client";

type Role = { id: string; name: string; permissions: string[] };
type Assignment = { id: string; roleId: string; subjectType: "user" | "team" | "service"; subjectId: string; resource: string; expiresAt: string | null; source: string };
type Request = { id: string; userId: string; role: string; reason: string; durationMinutes: number; status: string; expiresAt: string | null };
type Member = { userId: string; displayName: string };
type ServiceAccount = { id: string; name: string; clientId: string; disabled: boolean };

async function call<T>(url: string, body?: unknown): Promise<T> {
  const res = await fetch(url, {
    method: body === undefined ? "GET" : "POST",
    credentials: "include",
    cache: "no-store",
    headers: body === undefined ? {} : { "content-type": "application/json", "x-csrf-token": await getCsrf() },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = (await res.json().catch(() => ({}))) as T & { message?: string };
  if (!res.ok) throw new Error(data.message ?? "Something went wrong");
  return data;
}

/**
 * Access in an organization (lib/authz): roles, who holds them, service
 * accounts, and requests for temporary access. Everyone sees the roles and
 * can ask for one for a while; admins with the access area manage the rest.
 */
export function SpaceAccess({ spaceId, members, canManage }: { spaceId: string; members: Member[]; canManage: boolean }) {
  const [roles, setRoles] = useState<Role[]>([]);
  const [assignments, setAssignments] = useState<Assignment[]>([]);
  const [requests, setRequests] = useState<Request[]>([]);
  const [accounts, setAccounts] = useState<ServiceAccount[]>([]);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [roleName, setRoleName] = useState("");
  const [rolePermissions, setRolePermissions] = useState("");
  const [assignRoleId, setAssignRoleId] = useState("");
  const [assignTo, setAssignTo] = useState("");
  const [requestRoleId, setRequestRoleId] = useState("");
  const [requestMinutes, setRequestMinutes] = useState("60");
  const [requestReason, setRequestReason] = useState("");
  const nameOf = (a: Assignment) =>
    a.subjectType === "user" ? members.find((m) => m.userId === a.subjectId)?.displayName ?? "someone"
      : a.subjectType === "service" ? `${accounts.find((s) => s.id === a.subjectId)?.name ?? "a service account"} (service)`
        : "a team";

  const fetchAll = useCallback(async () => {
    const [access, reqs, services] = await Promise.all([
      call<{ roles: Role[]; assignments: Assignment[] }>(`/api/spaces/${spaceId}/access`),
      call<{ requests: Request[] }>(`/api/spaces/${spaceId}/access/requests`),
      canManage ? call<{ serviceAccounts: ServiceAccount[] }>(`/api/spaces/${spaceId}/service-accounts`) : Promise.resolve({ serviceAccounts: [] as ServiceAccount[] }),
    ]);
    return { access, reqs, services };
  }, [spaceId, canManage]);

  const show = useCallback((data: Awaited<ReturnType<typeof fetchAll>>) => {
    setRoles(data.access.roles);
    setAssignments(data.access.assignments);
    setRequests(data.reqs.requests);
    setAccounts(data.services.serviceAccounts);
  }, []);

  const load = useCallback(async () => show(await fetchAll()), [fetchAll, show]);

  useEffect(() => {
    let alive = true;
    void fetchAll()
      .then((data) => { if (alive) show(data); })
      .catch((error: Error) => { if (alive) setMessage(error.message); });
    return () => { alive = false; };
  }, [fetchAll, show]);

  async function run(work: () => Promise<unknown>, done: string) {
    setBusy(true);
    setMessage("");
    try {
      await work();
      await load();
      setMessage(done);
    } catch (error) {
      setMessage((error as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const access = (body: unknown) => call(`/api/spaces/${spaceId}/access`, body);
  const requestsCall = (body: unknown) => call(`/api/spaces/${spaceId}/access/requests`, body);
  const input = "h-9 rounded-xl border border-[var(--hairline)] bg-transparent px-2 text-sm";

  return (
    <section aria-labelledby={`access-${spaceId}`} className="space-y-3 rounded-xl border border-[var(--hairline)] p-4">
      <h3 id={`access-${spaceId}`} className="text-sm font-semibold">Access</h3>
      <p className="text-xs text-[var(--muted-foreground)]">Roles grant permissions in apps that ask Identity. Nothing is allowed unless a role grants it.</p>
      {message ? <p role="status" className="text-xs">{message}</p> : null}

      <ul aria-label="Roles" className="space-y-1 text-sm">
        {roles.map((role) => (
          <li key={role.id}>
            <span className="font-medium">{role.name}</span> <span className="font-mono text-[11px] text-[var(--muted-foreground)]">{role.permissions.join(" ")}</span>
            <ul className="ml-4 text-xs text-[var(--muted-foreground)]">
              {assignments.filter((a) => a.roleId === role.id).map((a) => (
                <li key={a.id}>
                  {nameOf(a)}{a.resource !== "*" ? ` on ${a.resource}` : ""}{a.expiresAt ? ` until ${new Date(a.expiresAt).toLocaleString()}` : ""}
                  {canManage ? (
                    <button type="button" className="ml-2 underline" disabled={busy} onClick={() => void run(() => access({ action: "unassign", assignmentId: a.id }), "Removed.")}>
                      Remove<span className="sr-only"> {role.name} from {nameOf(a)}</span>
                    </button>
                  ) : null}
                </li>
              ))}
            </ul>
          </li>
        ))}
      </ul>

      {canManage ? (
        <>
          <form className="flex flex-wrap gap-2" onSubmit={(e: FormEvent) => { e.preventDefault(); void run(() => access({ action: "save-role", name: roleName, permissions: rolePermissions.split(/[\s,]+/).filter(Boolean) }), "Role saved.").then(() => { setRoleName(""); setRolePermissions(""); }); }}>
            <input aria-label="Role name" placeholder="Role name" value={roleName} onChange={(e) => setRoleName(e.target.value)} className={input} />
            <input aria-label="Permissions" placeholder="invoice:read invoice:approve" value={rolePermissions} onChange={(e) => setRolePermissions(e.target.value)} className={`${input} min-w-[14rem] flex-1`} />
            <button type="submit" disabled={busy || !roleName.trim()} className="rounded-xl border border-[var(--hairline)] px-3 text-sm disabled:opacity-50">Add role</button>
          </form>
          <form className="flex flex-wrap gap-2" onSubmit={(e: FormEvent) => {
            e.preventDefault();
            const [subjectType, subjectId] = assignTo.split(":");
            void run(() => access({ action: "assign", roleId: assignRoleId, subjectType, subjectId }), "Role given.");
          }}>
            <select aria-label="Role to give" value={assignRoleId} onChange={(e) => setAssignRoleId(e.target.value)} className={input}>
              <option value="">Role…</option>
              {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
            </select>
            <select aria-label="Give it to" value={assignTo} onChange={(e) => setAssignTo(e.target.value)} className={input}>
              <option value="">To…</option>
              {members.map((m) => <option key={m.userId} value={`user:${m.userId}`}>{m.displayName}</option>)}
              {accounts.filter((s) => !s.disabled).map((s) => <option key={s.id} value={`service:${s.id}`}>{s.name} (service)</option>)}
            </select>
            <button type="submit" disabled={busy || !assignRoleId || !assignTo} className="rounded-xl border border-[var(--hairline)] px-3 text-sm disabled:opacity-50">Give role</button>
          </form>
          <div className="space-y-1 text-sm">
            <p className="text-xs font-medium">Service accounts</p>
            {accounts.map((s) => (
              <p key={s.id} className="text-xs">
                {s.name} <span className="font-mono text-[var(--muted-foreground)]">{s.clientId}</span> {s.disabled ? "(disabled)" : (
                  <button type="button" className="underline" disabled={busy} onClick={() => window.confirm(`Disable ${s.name}? Its tokens stop at once.`) && void run(() => call(`/api/spaces/${spaceId}/service-accounts`, { action: "disable", serviceAccountId: s.id }), "Disabled.")}>Disable</button>
                )}
              </p>
            ))}
            <button type="button" className="text-xs underline" disabled={busy} onClick={() => {
              const name = window.prompt("Name the service account (say, Nightly export)");
              if (!name) return;
              void run(async () => {
                const created = await call<{ serviceAccount: ServiceAccount; clientSecret: string }>(`/api/spaces/${spaceId}/service-accounts`, { action: "create", name });
                window.prompt("Its secret, shown once. Copy it now:", `${created.serviceAccount.clientId}:${created.clientSecret}`);
              }, "Service account created.");
            }}>
              New service account
            </button>
          </div>
        </>
      ) : null}

      <form className="flex flex-wrap gap-2" onSubmit={(e: FormEvent) => { e.preventDefault(); void run(() => requestsCall({ action: "request", roleId: requestRoleId, durationMinutes: Number(requestMinutes), reason: requestReason }), "Request sent.").then(() => setRequestReason("")); }}>
        <select aria-label="Role to ask for" value={requestRoleId} onChange={(e) => setRequestRoleId(e.target.value)} className={input}>
          <option value="">Ask for a role…</option>
          {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
        </select>
        <select aria-label="For how long" value={requestMinutes} onChange={(e) => setRequestMinutes(e.target.value)} className={input}>
          {[15, 60, 240, 1440].map((m) => <option key={m} value={m}>{m < 60 ? `${m} minutes` : m < 1440 ? `${m / 60} hour${m === 60 ? "" : "s"}` : "1 day"}</option>)}
        </select>
        <input aria-label="Why" placeholder="Why you need it" value={requestReason} onChange={(e) => setRequestReason(e.target.value)} className={`${input} min-w-[12rem] flex-1`} />
        <button type="submit" disabled={busy || !requestRoleId || requestReason.trim().length < 5} className="rounded-xl border border-[var(--hairline)] px-3 text-sm disabled:opacity-50">Ask</button>
      </form>
      {requests.length ? (
        <ul aria-label="Access requests" className="space-y-1 text-xs">
          {requests.map((r) => (
            <li key={r.id}>
              {members.find((m) => m.userId === r.userId)?.displayName ?? "Someone"} asked for {r.role} for {r.durationMinutes} min: &ldquo;{r.reason}&rdquo; ({r.status}{r.expiresAt ? `, until ${new Date(r.expiresAt).toLocaleString()}` : ""})
              {canManage && r.status === "pending" ? (
                <>
                  <button type="button" className="ml-2 underline" disabled={busy} onClick={() => void run(() => requestsCall({ action: "approve", requestId: r.id }), "Approved.")}>Approve</button>
                  <button type="button" className="ml-2 underline" disabled={busy} onClick={() => void run(() => requestsCall({ action: "deny", requestId: r.id }), "Declined.")}>Decline</button>
                </>
              ) : null}
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}
