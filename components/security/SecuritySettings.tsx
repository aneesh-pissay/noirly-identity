"use client";
import { useEffect, useState } from "react";
import { startRegistration } from "@simplewebauthn/browser";
import type { PublicKeyCredentialCreationOptionsJSON } from "@simplewebauthn/browser";
import { FormField } from "@/components/auth-ui";
import { securityRequest } from "./client";
import type { AuthenticatorDetails, AuthenticatorKind } from "@/lib/security/authenticators";
import type { MfaSource } from "@/lib/security/factors";
import type { EnrollmentState } from "@/lib/security/enrollment";

type Key = { id: string; name: string; addedAt: string; lastUsedAt: string | null } & AuthenticatorDetails;
type Settings = { totpEnabled: boolean; totpEnabledAt: string | null; totpLastUsedAt: string | null; mfaRequired: boolean; mfaSources: MfaSource[]; enrollment: EnrollmentState; recoveryCodesRemaining: number; recoveryCodesLow: boolean; passkeys: Key[] };
const button = "rounded-xl border border-[var(--hairline)] px-4 py-3 text-sm focus-visible:outline-2 disabled:opacity-50";

/** "your own setting", "the Acme space", in a sentence. */
function sourcesText(sources: MfaSource[]) {
  const parts = sources.map((s) => (s.type === "account" ? "your own setting" : `the ${s.name} space`));
  return parts.length <= 1 ? (parts[0] ?? "") : `${parts.slice(0, -1).join(", ")} and ${parts.at(-1)}`;
}

/** Signing in needs a second step: for an app (`mfaFor`) on the way back to it (`returnTo`). */
export function SecuritySettings({ mfaFor = null, returnTo = null }: { mfaFor?: string | null; returnTo?: string | null } = {}) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [enrollment, setEnrollment] = useState<{ secret: string; uri: string } | null>(null);
  const [codes, setCodes] = useState<string[]>([]);
  const [code, setCode] = useState("");
  const [name, setName] = useState("My passkey");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [renaming, setRenaming] = useState<{ id: string; name: string } | null>(null);
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
  async function enrollPasskey(kind: AuthenticatorKind) {
    const { options, token } = await securityRequest<{ options: PublicKeyCredentialCreationOptionsJSON; token: string }>("/api/auth/security", { action: "passkey-options", kind });
    const response = await startRegistration({ optionsJSON: options });
    const added = await securityRequest<{ standalone: boolean }>("/api/auth/security", { action: "passkey-register", token, response, name });
    setMessage(kind === "security_key"
      ? `Security key saved${added.standalone ? "" : ". It works as a second step after your password or another sign-in, since it can't check a PIN or keep the key itself"}. Other Identity sessions have been signed out.`
      : "Passkey saved. Other Identity sessions have been signed out.");
  }
  return <section aria-labelledby="security-title" className="mx-auto my-8 w-full max-w-3xl space-y-6 rounded-2xl border border-[var(--hairline)] p-6">
    <h2 id="security-title" className="text-xl font-semibold">Sign-in security</h2>
    <p className="text-sm opacity-75">Use an authenticator app or a passkey to protect your account. Changing these settings requires a sign-in within the last five minutes.</p>
    <a href="/login?return_to=/account&reauth=1" className="text-sm underline">Sign in again to change security settings</a>
    {message && <p role="status" className="text-sm">{message}</p>}
    {!settings ? <p role="status">Loading security settings…</p> : <>
      {(settings.enrollment.state === "grace" || settings.enrollment.state === "overdue") && (
        <div role="alert" className="space-y-2 rounded-xl border border-[var(--hairline)] p-3 text-sm">
          {settings.enrollment.state === "grace" ? (
            <p>{settings.enrollment.spaces.length === 1 ? `The ${settings.enrollment.spaces[0]} space asks` : "Your spaces ask"} every member to use a second step at sign-in. You have {settings.enrollment.daysLeft} day{settings.enrollment.daysLeft === 1 ? "" : "s"} left to set one up (until {new Date(settings.enrollment.until).toLocaleDateString()}); after that, Noirly apps won&apos;t let you in until you do.</p>
          ) : (
            <p>{settings.enrollment.spaces.length === 1 ? `The ${settings.enrollment.spaces[0]} space requires` : "Your spaces require"} a second step at sign-in, and the time to set one up ended on {new Date(settings.enrollment.since).toLocaleDateString()}. Noirly apps won&apos;t let you in until you set one up below.</p>
          )}
          {returnTo && settings.enrollment.state === "grace" && <a href={returnTo} className="inline-block underline">Not now, continue</a>}
        </div>
      )}
      {returnTo && (settings.enrollment.state !== "grace" || settings.totpEnabled || settings.passkeys.length > 0) && (
        <div role="status" className="space-y-2 rounded-xl border border-[var(--hairline)] p-3 text-sm">
          <p>{mfaFor ? `${mfaFor} asks for` : "Your account needs"} a second step at sign-in. Set up an authenticator app, passkey or security key below, then carry on.</p>
          {settings.totpEnabled || settings.passkeys.length > 0
            ? <a href={returnTo} className="inline-block underline">Continue{mfaFor ? ` to ${mfaFor}` : ""}</a>
            : <p className="text-xs opacity-75">The way back appears here once one is set up.</p>}
        </div>
      )}
      {settings.mfaSources.some((s) => s.type === "space") && (
        <p className="rounded-xl border border-[var(--hairline)] p-3 text-sm">A second step at every sign-in is required by {sourcesText(settings.mfaSources)}, so the last authenticator app, passkey or security key can&apos;t be removed{settings.totpEnabled || settings.passkeys.length > 0 ? "" : ". Set one up below"}.</p>
      )}
      <label className="flex items-start gap-3 text-sm">
        <input type="checkbox" className="mt-1" checked={settings.mfaSources.some((s) => s.type === "account")} disabled={busy || (!settings.totpEnabled && settings.passkeys.length === 0)}
          onChange={(event) => { const required = event.target.checked; void run(async () => { await securityRequest("/api/auth/security", { action: "mfa-required", required }); setMessage(required ? "Your last second step can no longer be removed by mistake." : "Turned off."); }); }} />
        <span>
          Always require a second step for my account
          <span className="block text-xs opacity-75">You&apos;re already asked for one whenever you have one. This keeps the last one from being removed, by accident or by someone with your password.</span>
        </span>
      </label>
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
          <p className="text-xs opacity-75">
            {[settings.totpEnabledAt ? `Set up ${new Date(settings.totpEnabledAt).toLocaleDateString()}` : null, settings.totpLastUsedAt ? `last used ${new Date(settings.totpLastUsedAt).toLocaleDateString()}` : "not used yet"].filter(Boolean).join(" · ")}
          </p>
          <p className="text-sm">{settings.recoveryCodesRemaining} recovery codes remaining. Each recovery code works once.</p>
          {settings.recoveryCodesLow && <p role="alert" className="rounded-xl border border-[var(--hairline)] p-3 text-sm">{settings.recoveryCodesRemaining === 0 ? "You have no recovery codes left." : "You're running low on recovery codes."} Make a new set so you can still get in if you lose your authenticator app.</p>}
          <button className={button} disabled={busy} onClick={() => void run(async () => { const result = await securityRequest<{ recoveryCodes: string[] }>("/api/auth/security", { action: "recovery-replace" }); setCodes(result.recoveryCodes); setMessage("New recovery codes made. The old ones no longer work."); })}>Make new recovery codes</button>
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
        <h3 className="font-medium">Passkeys and security keys</h3>
        <p className="text-sm opacity-75">A passkey verified with your fingerprint, face, or device PIN completes sign-in without an authenticator code. A hardware security key (one you plug in or tap) works too; if it can&apos;t check a PIN, it&apos;s a second step after your password.</p>
        <FormField label="Name" value={name} onChange={(event) => setName(event.target.value)} maxLength={80} />
        <div className="flex flex-wrap gap-2">
          <button className={button} disabled={busy || !name.trim()} onClick={() => void run(() => enrollPasskey("passkey"))}>Add passkey</button>
          <button className={button} disabled={busy || !name.trim()} onClick={() => void run(() => enrollPasskey("security_key"))}>Add security key</button>
        </div>
        <ul className="divide-y divide-[var(--hairline)]">{settings.passkeys.map((key) => (
          <li key={key.id} data-kind={key.kindLabel} className="flex flex-wrap items-center justify-between gap-3 py-3">
            <span className="min-w-0">
              {renaming?.id === key.id ? (
                <form className="flex flex-wrap items-center gap-2" onSubmit={(event) => { event.preventDefault(); const next = renaming.name.trim(); void run(async () => { await securityRequest("/api/auth/security", { action: "passkey-rename", credentialId: key.id, name: next }); setRenaming(null); setMessage("Renamed."); }); }}>
                  <input aria-label={`New name for ${key.name}`} className="h-9 rounded-lg border border-[var(--hairline)] bg-[var(--surface-2)] px-2 text-sm" maxLength={80} value={renaming.name} onChange={(event) => setRenaming({ id: key.id, name: event.target.value })} />
                  <button type="submit" className={button} disabled={busy || !renaming.name.trim()}>Save</button>
                  <button type="button" className={button} onClick={() => setRenaming(null)}>Cancel</button>
                </form>
              ) : (
                <span className="block">{key.name} <span className="ml-1 text-xs opacity-75">{key.kindLabel}{key.model ? ` · ${key.model}` : ""}</span></span>
              )}
              <span className="block text-xs opacity-75">
                {[...key.notes, `Added ${new Date(key.addedAt).toLocaleDateString()}`, key.lastUsedAt ? `last used ${new Date(key.lastUsedAt).toLocaleDateString()}` : "not used yet"].join(" · ")}
              </span>
            </span>
            <span className="flex gap-2">
              {renaming?.id !== key.id && <button className={button} disabled={busy} onClick={() => setRenaming({ id: key.id, name: key.name })}>Rename <span className="sr-only">{key.name}</span></button>}
              <button className={button} disabled={busy} onClick={() => void run(async () => { await securityRequest("/api/auth/security", { action: "passkey-delete", credentialId: key.id }); setMessage(`${key.kindLabel} removed.`); })}>Remove <span className="sr-only">{key.name}</span></button>
            </span>
          </li>
        ))}</ul>
      </div>
    </>}
  </section>;
}
