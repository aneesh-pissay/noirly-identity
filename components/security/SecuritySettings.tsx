"use client";
import { useEffect, useState } from "react";
import { startRegistration } from "@simplewebauthn/browser";
import type { PublicKeyCredentialCreationOptionsJSON } from "@simplewebauthn/browser";
import { FormField } from "@/components/auth-ui";
import { securityRequest } from "./client";

type Settings = { totpEnabled: boolean; recoveryCodesRemaining: number; passkeys: { id: string; name: string }[] };
const button = "rounded-xl border border-[var(--hairline)] px-4 py-3 text-sm focus-visible:outline-2 disabled:opacity-50";

export function SecuritySettings() {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [enrollment, setEnrollment] = useState<{ secret: string; uri: string } | null>(null);
  const [codes, setCodes] = useState<string[]>([]);
  const [code, setCode] = useState("");
  const [name, setName] = useState("My passkey");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  async function load() {
    const response = await fetch("/api/auth/security", { cache: "no-store" });
    if (!response.ok) throw new Error("Unable to load security settings");
    setSettings(await response.json());
  }
  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/auth/security", { cache: "no-store", signal: controller.signal })
      .then(async (response) => { if (!response.ok) throw new Error("Unable to load security settings"); return response.json() as Promise<Settings>; })
      .then(setSettings)
      .catch(() => { if (!controller.signal.aborted) setMessage("Unable to load security settings"); });
    return () => controller.abort();
  }, []);
  async function run(action: () => Promise<void>) {
    setBusy(true); setMessage("");
    try { await action(); await load(); }
    catch (error) { setMessage(error instanceof Error ? error.message : "Security request failed"); }
    finally { setBusy(false); }
  }
  async function enrollPasskey() {
    const { options, token } = await securityRequest<{ options: PublicKeyCredentialCreationOptionsJSON; token: string }>("/api/auth/security", { action: "passkey-options" });
    const response = await startRegistration({ optionsJSON: options });
    await securityRequest("/api/auth/security", { action: "passkey-register", token, response, name });
    setMessage("Passkey saved. Other Identity sessions have been signed out.");
  }
  return <section aria-labelledby="security-title" className="mx-auto my-8 w-full max-w-3xl space-y-6 rounded-2xl border border-[var(--hairline)] p-6">
    <h2 id="security-title" className="text-xl font-semibold">Sign-in security</h2>
    <p className="text-sm opacity-75">Use an authenticator app or a passkey to protect your account. Changing these settings requires a sign-in within the last five minutes.</p>
    <a href="/login?return_to=/account&reauth=1" className="text-sm underline">Sign in again to change security settings</a>
    {message && <p role="status" className="text-sm">{message}</p>}
    {!settings ? <p role="status">Loading security settings…</p> : <>
      <div className="space-y-3">
        <h3 className="font-medium">Authenticator app — {settings.totpEnabled ? "enabled" : "not enabled"}</h3>
        {!settings.totpEnabled && !enrollment && <button className={button} disabled={busy} onClick={() => void run(async () => setEnrollment(await securityRequest("/api/auth/security", { action: "totp-start" })))}>Set up authenticator</button>}
        {enrollment && <div className="space-y-3">
          <p className="text-sm">Add this setup key in your authenticator app, then enter its six-digit code. Keep this key private.</p>
          <code className="block break-all rounded-lg bg-[var(--surface-2)] p-3 select-all">{enrollment.secret}</code>
          <a href={enrollment.uri} className="text-sm underline">Open authenticator app</a>
          <FormField label="Six-digit code" value={code} onChange={(event) => setCode(event.target.value)} inputMode="numeric" autoComplete="one-time-code" maxLength={6} />
          <button className={button} disabled={busy || !/^\d{6}$/.test(code)} onClick={() => void run(async () => { const result = await securityRequest<{ recoveryCodes: string[] }>("/api/auth/security", { action: "totp-confirm", code }); setCodes(result.recoveryCodes); setEnrollment(null); setCode(""); })}>Enable authenticator</button>
        </div>}
        {settings.totpEnabled && <>
          <p className="text-sm">{settings.recoveryCodesRemaining} recovery codes remaining. Each recovery code works once.</p>
          <FormField label="Code to disable authenticator" value={code} onChange={(event) => setCode(event.target.value)} autoComplete="one-time-code" maxLength={32} />
          <button className={button} disabled={busy || !code} onClick={() => void run(async () => { await securityRequest("/api/auth/security", { action: "totp-disable", code }); setCode(""); setCodes([]); setMessage("Authenticator disabled."); })}>Disable authenticator</button>
        </>}
        {codes.length > 0 && <div className="space-y-3 rounded-xl border border-[var(--hairline)] p-4">
          <h4 className="font-medium">Save your recovery codes now</h4>
          <p className="text-sm">They will not be shown again. Store them somewhere private outside this device.</p>
          <pre className="overflow-x-auto text-sm select-all">{codes.join("\n")}</pre>
          <button className={button} onClick={() => { const url = URL.createObjectURL(new Blob([codes.join("\n")], { type: "text/plain" })); const a = document.createElement("a"); a.href = url; a.download = "noirly-recovery-codes.txt"; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 60_000); }}>Download recovery codes</button>
          <button className={button} onClick={() => setCodes([])}>I saved my codes</button>
        </div>}
      </div>
      <div className="space-y-3 border-t border-[var(--hairline)] pt-5">
        <h3 className="font-medium">Passkeys</h3>
        <p className="text-sm opacity-75">A passkey verified with your fingerprint, face, or device PIN completes sign-in without an authenticator code.</p>
        <FormField label="Passkey name" value={name} onChange={(event) => setName(event.target.value)} maxLength={80} />
        <button className={button} disabled={busy || !name.trim()} onClick={() => void run(enrollPasskey)}>Add passkey</button>
        <ul className="space-y-2">{settings.passkeys.map((key) => <li key={key.id} className="flex items-center justify-between gap-3"><span>{key.name}</span><button className={button} disabled={busy} onClick={() => void run(async () => { await securityRequest("/api/auth/security", { action: "passkey-delete", credentialId: key.id }); setMessage("Passkey removed."); })}>Remove <span className="sr-only">{key.name}</span></button></li>)}</ul>
      </div>
    </>}
  </section>;
}
