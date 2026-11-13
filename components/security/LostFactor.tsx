"use client";
import { useState } from "react";
import { goReturnTo } from "@/lib/auth/return-to";
import type { RecoveryStatus } from "@/lib/security/recovery";
import { securityRequest } from "./client";

const button = "rounded-xl border border-[var(--hairline)] px-3 py-2 text-sm focus-visible:outline-2 disabled:opacity-50";

/** On the verification screen: what to do when the second step is lost. */
export function LostFactor({ returnTo }: { returnTo: string | null }) {
  const [open, setOpen] = useState(false);
  const [status, setStatus] = useState<RecoveryStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [codeSent, setCodeSent] = useState(false);
  const [code, setCode] = useState("");

  async function call(action: "status" | "send-code" | "start" | "finish") {
    setBusy(true);
    setMessage("");
    try {
      if (action === "finish") {
        await securityRequest("/api/auth/recovery", { action });
        goReturnTo(returnTo ?? "/account/security#security-title");
        return;
      }
      if (action === "send-code") {
        await securityRequest("/api/auth/recovery", { action });
        setCodeSent(true);
        return;
      }
      setStatus(await securityRequest<RecoveryStatus>("/api/auth/recovery", action === "start" ? { action, code } : { action }));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }

  if (!open) {
    return <button type="button" className="text-sm underline" onClick={() => { setOpen(true); void call("status"); }}>Lost your authenticator app, passkey or security key?</button>;
  }

  const hasMethod = status?.state === "none" && status.hasRecoveryMethod;
  return <section aria-label="Lost second step" className="space-y-3 rounded-xl border border-[var(--hairline)] p-4 text-sm">
    <p>
      A recovery code works in place of any of them. Without one, you can ask to remove your second steps. To keep your account safe it takes {hasMethod ? "24 hours" : "72 hours (24 with a recovery address or phone)"},
      and we tell every address and phone on your account so you can stop it if it isn&apos;t you.
    </p>
    {message && <p role="alert">{message}</p>}
    {!status ? <p role="status">Checking…</p>
      : status.state === "none" ? (
        hasMethod ? (
          <div className="space-y-2">
            {!codeSent ? <button type="button" className={button} disabled={busy} onClick={() => void call("send-code")}>Send a code to my recovery address or phone</button> : (
              <form className="flex flex-wrap gap-2" onSubmit={(e) => { e.preventDefault(); void call("start"); }}>
                <label className="sr-only" htmlFor="recovery-code">Recovery code</label>
                <input id="recovery-code" value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" maxLength={6} className="h-9 rounded-xl border border-[var(--hairline)] bg-transparent px-3" placeholder="6-digit code" />
                <button type="submit" className={button} disabled={busy || code.trim().length !== 6}>Ask to remove my second steps</button>
              </form>
            )}
          </div>
        ) : <button type="button" className={button} disabled={busy} onClick={() => void call("start")}>Ask to remove my second steps</button>
      )
      : status.state === "waiting" ? <p role="status">Requested. You can finish after {new Date(status.availableAt).toLocaleString()}: sign in again then, and come back here.</p>
      : status.state === "review" ? <p role="status">Requested. Because it came from somewhere new, our team looks at it first; we&apos;ll email you. It can be finished after {new Date(status.availableAt).toLocaleString()} once approved.</p>
      : <div className="space-y-2">
          <p>The wait is over. Finishing removes your authenticator app, recovery codes, passkeys and security keys, and signs out your other devices. Set up a new one straight away.</p>
          <button type="button" className={button} disabled={busy} onClick={() => void call("finish")}>Remove them and sign in</button>
        </div>}
  </section>;
}
