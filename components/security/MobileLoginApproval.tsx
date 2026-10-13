"use client";
import { useState, type FormEvent } from "react";
import { FormField } from "@/components/auth-ui";
import { securityRequest } from "./client";

export function MobileLoginApproval({ request, appName, email }: { request: string; appName: string; email: string }) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState("");
  async function approve(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError("");
    try { await securityRequest("/api/mobile/browser-login", { action: "approve", request, code }); setDone(true); }
    catch (error) { setError(error instanceof Error ? error.message : "Approval failed"); }
    finally { setBusy(false); }
  }
  if (done) return <div className="space-y-4"><h1 className="text-2xl font-semibold">You’re signed in</h1><p>Return to the mobile app to continue.</p><a href="noirlyflow://signin-approved" className="underline">Open Flow</a></div>;
  return <form onSubmit={approve} className="space-y-5">
    <h1 className="text-2xl font-semibold">Sign in to {appName}</h1>
    <p>Continue as <strong>{email}</strong>.</p>
    <p className="text-sm">Enter the six-digit code shown in your mobile app. Only approve a sign-in you started yourself.</p>
    <FormField label="Code shown in the mobile app" value={code} onChange={(event) => setCode(event.target.value)} inputMode="numeric" maxLength={6} required />
    {error && <p role="alert">{error}</p>}
    <button className="w-full rounded-xl bg-[var(--accent)] px-4 py-3 text-[var(--accent-foreground)] disabled:opacity-50" disabled={busy || !/^\d{6}$/.test(code)}>{busy ? "Approving…" : "Approve mobile sign-in"}</button>
    <a className="block text-sm underline" href={`/login?select_account=1&return_to=${encodeURIComponent(`/mobile-login?request=${encodeURIComponent(request)}`)}`}>Use another account</a>
  </form>;
}
