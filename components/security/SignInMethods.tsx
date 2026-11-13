"use client";
import { useEffect, useState } from "react";
import { getCsrf } from "@/lib/auth/csrf-client";
import { FormField } from "@/components/auth-ui";
import { securityRequest } from "./client";
import { methodCount, PROVIDER_LABEL, PROVIDERS, providerStartPath, type Provider, type SignInMethods as Methods } from "@/lib/account/sign-in-methods";

const button = "rounded-xl border border-[var(--hairline)] px-3 py-2 text-sm focus-visible:outline-2 disabled:opacity-50";
/** Why linking didn't happen, by the code it came back with. */
const LINK_ERRORS: Record<string, (label: string) => string> = {
  reauth_required: (label) => `Sign in again, then link ${label} within five minutes.`,
  unauthorized: (label) => `Sign in to link ${label}.`,
  session_changed: (label) => `Your session changed while you were at ${label}. Try again.`,
  linked_elsewhere: (label) => `That ${label} account is already linked to another Noirly account.`,
  already_linked: (label) => `Another ${label} account is already linked. Unlink it first.`,
};

function firstMessage(linked: string | null, linkError: string | null, provider: string | null) {
  const known = (value: string | null): value is Provider => (PROVIDERS as readonly string[]).includes(value ?? "");
  if (known(linked)) return `${PROVIDER_LABEL[linked]} is linked to your account.`;
  if (!linkError) return "";
  const label = known(provider) ? PROVIDER_LABEL[provider] : "That account";
  return LINK_ERRORS[linkError]?.(label) ?? `${label} couldn't be linked. Try again.`;
}

/**
 * Every way into the account (the last one can't be removed), then the
 * provider accounts linked to it. Linked accounts never sign anyone in.
 */
export function SignInMethods({ linked, linkError, provider }: { linked: string | null; linkError: string | null; provider: string | null }) {
  const [methods, setMethods] = useState<Methods | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(() => firstMessage(linked, linkError, provider));
  const [addingPassword, setAddingPassword] = useState(false);
  const [newPassword, setNewPassword] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/auth/identities", { cache: "no-store", signal: controller.signal })
      .then(async (response) => { if (!response.ok) throw new Error(); return response.json() as Promise<Methods>; })
      .then(setMethods)
      .catch(() => { if (!controller.signal.aborted) setMessage("Unable to load sign-in methods"); });
    return () => controller.abort();
  }, []);

  /** Adds or removes the password; both need a recent sign-in. */
  async function passwordAction(body: Record<string, unknown>, done: string) {
    setBusy(true);
    setMessage("");
    try {
      setMethods(await securityRequest<Methods>("/api/auth/password", body));
      setMessage(done);
      return true;
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Request failed");
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function unlink(provider: string) {
    setBusy(true);
    setMessage("");
    try {
      const res = await fetch("/api/auth/identities", { method: "DELETE", credentials: "same-origin", headers: { "content-type": "application/json", "x-csrf-token": await getCsrf() }, body: JSON.stringify({ provider }) });
      const data = (await res.json()) as Methods & { message?: string };
      if (!res.ok) throw new Error(data.message ?? "Could not unlink");
      setMethods(data);
      setMessage(`${PROVIDER_LABEL[provider as Provider] ?? provider} unlinked.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not unlink");
    } finally {
      setBusy(false);
    }
  }

  const total = methods ? methodCount({ password: methods.password, passkeys: methods.passkeys }) : 0;
  const last = total === 1;

  return <section id="sign-in-methods" aria-labelledby="methods-title" className="mx-auto my-8 w-full max-w-3xl scroll-mt-8 space-y-5 rounded-2xl border border-[var(--hairline)] p-6">
    <h2 id="methods-title" className="text-xl font-semibold">Ways to sign in</h2>
    <p className="text-sm opacity-75">Sign in with your email address and a password, an emailed link or code, or a passkey. Your only password or passkey can&apos;t be removed. Adding, removing, linking or unlinking needs a sign-in within the last five minutes.</p>
    {message && <p role="status" className="text-sm">{message}</p>}
    {!methods ? <p role="status">Loading sign-in methods…</p> : (
      <ul aria-label="Ways to sign in" className="divide-y divide-[var(--hairline)]">
        <li className="flex flex-col gap-3 py-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span>Password <span className="ml-2 text-xs opacity-75">{methods.password ? "Set" : "Not set"}</span></span>
            {methods.password ? (
              <span className="flex flex-wrap items-center gap-3">
                <a href="#password" className="text-sm underline">Change</a>
                <button type="button" className={button} disabled={busy || last} title={last ? "Your only way to sign in" : undefined} onClick={() => void passwordAction({ action: "remove" }, "Password removed. Other sessions were signed out.")}>Remove</button>
              </span>
            ) : !addingPassword ? (
              <button type="button" className={button} disabled={busy} onClick={() => setAddingPassword(true)}>Add a password</button>
            ) : null}
          </div>
          {!methods.password && addingPassword ? (
            <form className="flex flex-col gap-3" onSubmit={(event) => { event.preventDefault(); void passwordAction({ action: "set", password: newPassword }, "Password added.").then((ok) => { if (ok) { setNewPassword(""); setAddingPassword(false); } }); }}>
              <FormField label="New password" type="password" autoComplete="new-password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} />
              <div className="flex gap-2">
                <button type="submit" className={button} disabled={busy || !newPassword}>Save password</button>
                <button type="button" className={button} onClick={() => { setAddingPassword(false); setNewPassword(""); }}>Cancel</button>
              </div>
            </form>
          ) : null}
        </li>
        <li className="flex flex-wrap items-center justify-between gap-2 py-3">
          <span>Passkeys <span className="ml-2 text-xs opacity-75">{methods.passkeys ? `${methods.passkeys} saved` : "None"}</span></span>
          <a href="#security-title" className="text-sm underline">Manage</a>
        </li>
        <li className="flex flex-wrap items-center justify-between gap-2 py-3">
          <span>Emailed sign-in link <span className="ml-2 text-xs opacity-75">Always available, sent to your primary email address</span></span>
        </li>
      </ul>
    )}
    {methods && last && <p className="text-sm opacity-75">This is your only password or passkey. Add another before removing it.</p>}
    {methods && methods.providers.length ? (
      <div className="space-y-2 border-t border-[var(--hairline)] pt-5">
        <h3 className="font-medium">Linked accounts</h3>
        <p className="text-sm opacity-75">Link your Google, Apple, Microsoft or GitHub account to show it&apos;s yours. Linked accounts never sign you in to Noirly.</p>
        <ul aria-label="Linked accounts" className="divide-y divide-[var(--hairline)]">
          {methods.providers.map((p) => (
            <li key={p.provider} data-provider={p.provider} className="flex flex-wrap items-center justify-between gap-2 py-3">
              <span>
                {PROVIDER_LABEL[p.provider]}
                <span className="ml-2 text-xs opacity-75">{p.linked ? `Linked${p.linked.email ? ` as ${p.linked.email}` : ""}` : "Not linked"}</span>
              </span>
              {p.linked
                ? <button type="button" className={button} disabled={busy} onClick={() => void unlink(p.provider)}>Unlink <span className="sr-only">{PROVIDER_LABEL[p.provider]}</span></button>
                : p.available
                  ? <a href={`${providerStartPath(p.provider)}?intent=link`} className={button}>Link {PROVIDER_LABEL[p.provider]}</a>
                  : <span className="text-xs opacity-75">Not available</span>}
            </li>
          ))}
        </ul>
      </div>
    ) : null}
  </section>;
}
