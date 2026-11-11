"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { securityRequest } from "./client";

/** "Freeze my account": stops every sign-in at once, until unfrozen a day after confirming by email. */
export function FreezeAccount() {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  async function freeze() {
    if (!window.confirm("Freeze your account? Every device is signed out (this one too), apps lose access, and nobody can sign in until you unfreeze it, which takes a day after confirming by email.")) return;
    setBusy(true);
    try {
      await securityRequest("/api/auth/freeze", { action: "freeze" });
      router.push("/unfreeze");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "That didn't work");
      setBusy(false);
    }
  }
  return <section aria-labelledby="freeze-title" className="mx-auto my-8 w-full max-w-3xl space-y-3 rounded-2xl border border-[var(--hairline)] p-6">
    <h2 id="freeze-title" className="text-xl font-semibold">Freeze your account</h2>
    <p className="text-sm opacity-75">If you think someone else has your account, freeze it: nobody can sign in, and every device and app is cut off at once. Every security alert we email has a link to do this too.</p>
    {message && <p role="alert" className="text-sm">{message}</p>}
    <button type="button" disabled={busy} onClick={() => void freeze()} className="rounded-xl border border-[var(--hairline)] px-3 py-2 text-sm disabled:opacity-50">Freeze my account</button>
  </section>;
}
