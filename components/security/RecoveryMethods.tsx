"use client";
import { FormEvent, useEffect, useState } from "react";
import { securityRequest } from "./client";

type Methods = { email: string | null; pendingEmail: string | null; phone: string | null };
const button = "rounded-xl border border-[var(--hairline)] px-3 py-2 text-sm focus-visible:outline-2 disabled:opacity-50";

/** Recovery address and phone: only for getting back in when a second step is lost, never for signing in. */
export function RecoveryMethods() {
  const [methods, setMethods] = useState<Methods | null>(null);
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/auth/recovery-methods", { cache: "no-store", signal: controller.signal })
      .then(async (res) => (res.ok ? ((await res.json()) as Methods) : null))
      .then(setMethods)
      .catch(() => undefined);
    return () => controller.abort();
  }, []);

  async function act(body: Record<string, string>, done: string) {
    setBusy(true);
    setMessage("");
    try {
      setMethods(await securityRequest<Methods>("/api/auth/recovery-methods", body));
      setMessage(done);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "That didn't work");
    } finally {
      setBusy(false);
    }
  }

  return <section aria-labelledby="recovery-methods-title" className="mx-auto my-8 w-full max-w-3xl space-y-4 rounded-2xl border border-[var(--hairline)] p-6">
    <h2 id="recovery-methods-title" className="text-xl font-semibold">Recovery address and phone</h2>
    <p className="text-sm opacity-75">If you ever lose your second step, a code sent here proves it&apos;s you and shortens the wait to remove it. They&apos;re never used to sign in, and apps never see them. Changes need a recent sign-in.</p>
    {message && <p role="status" className="text-sm">{message}</p>}
    {!methods ? <p role="status">Loading…</p> : <>
      <p className="text-sm">Phone: {methods.phone ?? "none (add a verified phone above)"}</p>
      {methods.email ? (
        <p className="text-sm">
          Recovery address: {methods.email}{" "}
          <button type="button" className="underline" disabled={busy} onClick={() => void act({ action: "remove-email" }, "Removed.")}>Remove</button>
        </p>
      ) : methods.pendingEmail ? (
        <form className="flex flex-wrap items-end gap-2" onSubmit={(e: FormEvent) => { e.preventDefault(); void act({ action: "confirm-email", code }, "Recovery address confirmed."); }}>
          <label className="text-sm">Code sent to {methods.pendingEmail}
            <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" maxLength={6} className="ml-2 h-9 rounded-xl border border-[var(--hairline)] bg-transparent px-2" />
          </label>
          <button type="submit" className={button} disabled={busy || code.trim().length !== 6}>Confirm</button>
        </form>
      ) : (
        <form className="flex flex-wrap items-end gap-2" onSubmit={(e: FormEvent) => { e.preventDefault(); void act({ action: "start-email", email }, "We sent a code to that address."); }}>
          <label className="text-sm">Recovery address
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} className="ml-2 h-9 rounded-xl border border-[var(--hairline)] bg-transparent px-2" placeholder="an address you don't sign in with" />
          </label>
          <button type="submit" className={button} disabled={busy || !email}>Send a code</button>
        </form>
      )}
    </>}
  </section>;
}
