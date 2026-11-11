"use client";

import { FormEvent, useEffect, useState } from "react";
import { AuthShell } from "@noirly-dev/ui";
import { AuthLogo } from "@/components/AuthLogo";
import { FormField, Notice, SubmitButton, TextLink } from "@/components/auth-ui";
import { getCsrf } from "@/lib/auth/csrf-client";

/** Admin: contain an account that may have been taken over, or unlock it. */
export function AdminSecurity() {
  const [email, setEmail] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reviews, setReviews] = useState<Array<{ id: string; email: string; startedAt: string; availableAt: string; signals: string[]; verifiedByRecoveryMethod: boolean }>>([]);

  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/admin/recoveries", { credentials: "include", cache: "no-store", signal: controller.signal })
      .then(async (res) => (res.ok ? ((await res.json()) as { recoveries: typeof reviews }).recoveries : []))
      .then(setReviews)
      .catch(() => undefined);
    return () => controller.abort();
  }, []);

  async function decide(id: string, approve: boolean) {
    setBusy(true);
    try {
      const res = await fetch("/api/admin/recoveries", { method: "POST", credentials: "include", headers: { "content-type": "application/json", "x-csrf-token": await getCsrf() }, body: JSON.stringify({ id, approve }) });
      const data = (await res.json()) as { recoveries?: typeof reviews; message?: string };
      if (!res.ok) throw new Error(data.message ?? "That didn't work");
      setReviews(data.recoveries ?? []);
      setNotice(approve ? "Approved: they can finish after the wait." : "Declined.");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function act(action: "contain" | "unlock") {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = await fetch("/api/admin/accounts", {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json", "x-csrf-token": await getCsrf() },
        body: JSON.stringify(action === "contain" ? { action, email, reason } : { action, email }),
      });
      const data = (await res.json()) as { message?: string; sessionsEnded?: number; tokensRevoked?: number };
      if (!res.ok) throw new Error(data.message ?? "That didn't work");
      setNotice(action === "contain" ? `Locked. ${data.sessionsEnded ?? 0} sessions ended, ${data.tokensRevoked ?? 0} app tokens revoked, password removed.` : "Unlocked. They've been sent a link to choose a new password.");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell logo={<AuthLogo />} title="Account protection" lead="When an account may have been taken over: lock it, sign it out everywhere, cut off its apps and force a new password, in one step." footer={<TextLink href="/account">Back to account</TextLink>}>
      <form
        className="flex flex-col gap-4"
        onSubmit={(event: FormEvent) => {
          event.preventDefault();
          if (window.confirm(`Lock ${email}? They're signed out everywhere and must choose a new password once unlocked.`)) void act("contain");
        }}
      >
        <FormField label="Account email" name="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        <FormField label="Why (kept in the admin log)" name="reason" value={reason} onChange={(e) => setReason(e.target.value)} />
        {error ? <Notice tone="error">{error}</Notice> : null}
        {notice ? <Notice tone="success">{notice}</Notice> : null}
        <SubmitButton busy={busy} busyLabel="Locking…" disabled={!email || reason.trim().length < 5}>Lock and contain</SubmitButton>
        <button type="button" className="text-sm underline" disabled={busy || !email} onClick={() => void act("unlock")}>Unlock instead</button>
        <p className="text-xs text-[var(--muted-foreground)]">Both need a sign-in in the last few minutes.</p>
      </form>
      <section aria-labelledby="reviews-title" className="mt-8 space-y-2 border-t border-[var(--hairline)] pt-6">
        <h2 id="reviews-title" className="text-lg font-semibold">Recoveries to review</h2>
        <p className="text-xs text-[var(--muted-foreground)]">Requests to remove a second step that came from somewhere risky. Approve only if you&apos;re confident it&apos;s the owner.</p>
        {reviews.length === 0 ? <p className="text-sm">Nothing waiting.</p> : (
          <ul className="space-y-2 text-sm">
            {reviews.map((r) => (
              <li key={r.id} className="rounded-xl border border-[var(--hairline)] p-3">
                <p className="font-medium">{r.email}</p>
                <p className="text-xs text-[var(--muted-foreground)]">Started {new Date(r.startedAt).toLocaleString()} · {r.signals.join(", ").replace(/_/g, " ") || "no signals"} · {r.verifiedByRecoveryMethod ? "proved with a recovery method" : "no recovery method"}</p>
                <div className="mt-2 flex gap-3">
                  <button type="button" className="underline" disabled={busy} onClick={() => void decide(r.id, true)}>Approve</button>
                  <button type="button" className="underline" disabled={busy} onClick={() => void decide(r.id, false)}>Decline</button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>
    </AuthShell>
  );
}
