"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { getCsrf } from "@/lib/auth/csrf-client";

type Joinable = { id: string; name: string; domain: string };

/** Spaces you can join without an invitation, through your work address's verified domain. */
export function JoinableSpaces() {
  const router = useRouter();
  const [spaces, setSpaces] = useState<Joinable[]>([]);
  const [message, setMessage] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/spaces/joinable", { credentials: "include", cache: "no-store", signal: controller.signal })
      .then(async (res) => (res.ok ? ((await res.json()) as { spaces: Joinable[] }).spaces : []))
      .then(setSpaces)
      .catch(() => undefined);
    return () => controller.abort();
  }, []);

  async function join(space: Joinable) {
    setMessage("");
    const res = await fetch(`/api/spaces/${space.id}/join`, { method: "POST", credentials: "include", headers: { "x-csrf-token": await getCsrf() } });
    if (!res.ok) {
      setMessage(((await res.json().catch(() => ({}))) as { message?: string }).message ?? "Couldn't join");
      return;
    }
    setSpaces((current) => current.filter((s) => s.id !== space.id));
    setMessage(`You joined ${space.name}.`);
    router.refresh();
  }

  if (!spaces.length && !message) return null;
  return (
    <section aria-labelledby="joinable-title" className="mx-auto my-6 w-full max-w-3xl space-y-3 rounded-2xl border border-[var(--hairline)] p-6">
      <h2 id="joinable-title" className="text-lg font-semibold">Spaces you can join</h2>
      {message ? <p role="status" className="text-sm">{message}</p> : null}
      <ul className="divide-y divide-[var(--hairline)]">
        {spaces.map((space) => (
          <li key={space.id} className="flex items-center justify-between gap-2 py-2 text-sm">
            <span>{space.name} <span className="text-xs text-[var(--muted-foreground)]">for {space.domain} addresses</span></span>
            <button type="button" className="rounded-xl border border-[var(--hairline)] px-3 py-1" onClick={() => void join(space)}>
              Join<span className="sr-only"> {space.name}</span>
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}
