"use client";

import { useEffect, useState } from "react";
import { AuthShell } from "@noirly-dev/ui";
import { AuthLogo } from "@/components/AuthLogo";
import { Notice, TextLink } from "@/components/auth-ui";
import { getCsrf } from "@/lib/auth/csrf-client";

type Review = { clientId: string; name: string; allowed: string[]; granted: Record<string, number>; unused: string[]; settling: boolean };

/** Admin: every app gets only the claims it needs. */
export function AdminClaims() {
  const [apps, setApps] = useState<Review[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    fetch("/api/admin/claims", { credentials: "include", cache: "no-store" })
      .then(async (res) => {
        const data = (await res.json()) as { apps?: Review[]; message?: string };
        if (!res.ok) throw new Error(data.message ?? "Couldn't load the review");
        if (live) setApps(data.apps ?? []);
      })
      .catch((e: Error) => { if (live) setError(e.message); });
    return () => { live = false; };
  }, []);

  async function trim(clientId: string, remove: string[]) {
    setError(null);
    try {
      const res = await fetch("/api/admin/claims", { method: "POST", credentials: "include", headers: { "content-type": "application/json", "x-csrf-token": await getCsrf() }, body: JSON.stringify({ clientId, remove }) });
      const data = (await res.json()) as Review & { message?: string };
      if (!res.ok) throw new Error(data.message ?? "Couldn't trim");
      setApps((list) => list.map((a) => (a.clientId === clientId ? data : a)));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Couldn't trim");
    }
  }

  return (
    <AuthShell logo={<AuthLogo />} title="Claim review" lead="What each app may ask for, against what people have actually granted it." size="lg" align="top" className="py-8" footer={<TextLink href="/clients">Apps</TextLink>}>
      <div className="space-y-4">
        {error && <Notice tone="error">{error}</Notice>}
        <ul className="space-y-3 text-sm">
          {apps.map((a) => (
            <li key={a.clientId} className="rounded-xl border border-[var(--hairline)] p-3">
              <p className="font-medium">{a.name} <code className="text-xs opacity-75">{a.clientId}</code></p>
              <p className="text-xs">{a.allowed.map((s) => `${s} (${a.granted[s] ?? 0})`).join(", ")}</p>
              {a.settling ? <p className="text-xs opacity-75">Registered under 30 days ago; too new to judge.</p>
                : a.unused.length ? (
                  <p className="mt-1 text-xs">Never granted: <strong>{a.unused.join(", ")}</strong>{" "}
                    <button type="button" onClick={() => void trim(a.clientId, a.unused)} className="ml-2 rounded-xl border border-[var(--hairline)] px-2 py-0.5">Remove them</button></p>
                ) : <p className="text-xs opacity-75">Only what it uses.</p>}
            </li>
          ))}
        </ul>
      </div>
    </AuthShell>
  );
}
