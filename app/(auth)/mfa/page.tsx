"use client";
import { Suspense, useState, type FormEvent } from "react";
import { useSearchParams } from "next/navigation";
import { goReturnTo, withReturnTo } from "@/lib/auth/return-to";
import { securityRequest } from "@/components/security/client";
import { PasskeySignIn } from "@/components/security/PasskeySignIn";
import { FormField } from "@/components/auth-ui";

function Verification() {
  const params = useSearchParams();
  const returnTo = params.get("return_to");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError("");
    try { await securityRequest("/api/auth/mfa", { action: "code", code: code.trim() }); goReturnTo(returnTo ?? "/account"); }
    catch (error) { setError(error instanceof Error ? error.message : "Verification failed"); }
    finally { setBusy(false); }
  }
  return <main className="mx-auto w-full max-w-md space-y-5 px-6 py-12">
    <h1 className="text-2xl font-semibold">Verify your sign-in</h1>
    <p className="text-sm opacity-75">Enter the code from your authenticator app, use a saved recovery code, or verify with your passkey.</p>
    <form onSubmit={submit} className="space-y-4">
      <FormField label="Authenticator or recovery code" value={code} onChange={(event) => setCode(event.target.value)} autoComplete="one-time-code" autoCapitalize="none" maxLength={32} required />
      {error && <p role="alert" className="text-sm text-red-500">{error}</p>}
      <button disabled={busy} className="w-full rounded-xl bg-[var(--accent)] px-4 py-3 text-[var(--accent-foreground)] disabled:opacity-50">{busy ? "Verifying…" : "Verify and continue"}</button>
    </form>
    <PasskeySignIn returnTo={returnTo} secondFactor />
    <a href={withReturnTo("/login", returnTo)} className="text-sm underline">Start sign-in again</a>
  </main>;
}
export default function MfaPage() { return <Suspense fallback={<p role="status">Loading verification…</p>}><Verification /></Suspense>; }
