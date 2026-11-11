"use client";
import { useEffect, useState } from "react";
import { FormField } from "@/components/auth-ui";
import type { EmailAddresses as Addresses } from "@/lib/account/emails";
import { securityRequest } from "./client";

const button = "rounded-xl border border-[var(--hairline)] px-3 py-2 text-sm focus-visible:outline-2 disabled:opacity-50";

/** The account's primary address and the others it can use, each confirmed by a link sent to it. */
export function EmailAddresses() {
  const [data, setData] = useState<Addresses | null>(null);
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/auth/emails", { cache: "no-store", signal: controller.signal })
      .then(async (response) => { if (!response.ok) throw new Error(); return response.json() as Promise<Addresses>; })
      .then(setData)
      .catch(() => { if (!controller.signal.aborted) setMessage("Unable to load email addresses"); });
    return () => controller.abort();
  }, []);

  async function run(body: Record<string, unknown>, done: string) {
    setBusy(true);
    setMessage("");
    try {
      const result = await securityRequest<Addresses | { ok: true }>("/api/auth/emails", body);
      if ("primary" in result) setData(result);
      setMessage(done);
      return true;
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Request failed");
      return false;
    } finally {
      setBusy(false);
    }
  }

  return <section aria-labelledby="emails-title" className="mx-auto my-8 w-full max-w-3xl space-y-5 rounded-2xl border border-[var(--hairline)] p-6">
    <h2 id="emails-title" className="text-xl font-semibold">Email addresses</h2>
    <p className="text-sm opacity-75">Your primary address is where sign-in links and security notices go, and what Noirly apps see. Other addresses can be made primary once confirmed. Changing the primary one needs a sign-in within the last five minutes, and the old address gets a link to undo it for seven days.</p>
    {message && <p role="status" className="text-sm">{message}</p>}
    {!data ? <p role="status">Loading email addresses…</p> : <>
      <ul aria-label="Email addresses" className="divide-y divide-[var(--hairline)]">
        <li className="flex flex-wrap items-center justify-between gap-2 py-3">
          <span className="break-all">{data.primary}</span>
          <span className="rounded-full border border-[var(--hairline)] px-2 py-0.5 text-xs">Primary</span>
        </li>
        {data.additional.map((a) => (
          <li key={a.id} data-email={a.email} className="flex flex-wrap items-center justify-between gap-2 py-3">
            <span className="break-all">
              {a.email}
              {!a.verified && <span className="ml-2 text-xs opacity-75">Waiting to be confirmed</span>}
            </span>
            <span className="flex flex-wrap gap-2">
              {a.verified
                ? <button type="button" className={button} disabled={busy} onClick={() => void run({ action: "make-primary", id: a.id }, `${a.email} is now your primary address.`)}>Make primary <span className="sr-only">{a.email}</span></button>
                : <button type="button" className={button} disabled={busy} onClick={() => void run({ action: "resend", id: a.id }, `Sent a new link to ${a.email}.`)}>Send link again <span className="sr-only">to {a.email}</span></button>}
              <button type="button" className={button} disabled={busy} onClick={() => void run({ action: "remove", id: a.id }, `Removed ${a.email}.`)}>Remove <span className="sr-only">{a.email}</span></button>
            </span>
          </li>
        ))}
      </ul>
      {data.additional.length < data.max
        ? <form className="flex flex-col gap-3" onSubmit={(event) => { event.preventDefault(); const value = email.trim(); void run({ action: "add", email: value }, `We sent a link to ${value}. Open it to confirm the address.`).then((ok) => { if (ok) setEmail(""); }); }}>
            <FormField label="Add an email address" type="email" value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="email" maxLength={320} />
            <button type="submit" className={`${button} self-start`} disabled={busy || !email.trim()}>Add address</button>
          </form>
        : <p className="text-sm opacity-75">You have the most addresses an account can have ({data.max}). Remove one to add another.</p>}
    </>}
  </section>;
}
