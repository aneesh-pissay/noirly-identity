"use client";
import { useEffect, useState } from "react";
import { FormField } from "@/components/auth-ui";
import type { PhoneState } from "@/lib/account/phone";
import { securityRequest } from "./client";

const button = "rounded-xl border border-[var(--hairline)] px-3 py-2 text-sm focus-visible:outline-2 disabled:opacity-50";

/** An optional phone number, verified by a texted code. Never a way to sign in on its own. */
export function PhoneNumber() {
  const [state, setState] = useState<PhoneState | null>(null);
  const [phone, setPhone] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/auth/phone", { cache: "no-store", signal: controller.signal })
      .then(async (response) => { if (!response.ok) throw new Error(); return response.json() as Promise<PhoneState>; })
      .then(setState)
      .catch(() => { if (!controller.signal.aborted) setMessage("Unable to load your phone number"); });
    return () => controller.abort();
  }, []);

  async function run(body: Record<string, unknown>, done: string) {
    setBusy(true);
    setMessage("");
    try {
      setState(await securityRequest<PhoneState>("/api/auth/phone", body));
      setMessage(done);
      return true;
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Request failed");
      return false;
    } finally {
      setBusy(false);
    }
  }

  if (state && !state.available && !state.phone) return null;

  return <section aria-labelledby="phone-title" className="mx-auto my-8 w-full max-w-3xl space-y-5 rounded-2xl border border-[var(--hairline)] p-6">
    <h2 id="phone-title" className="text-xl font-semibold">Phone number</h2>
    <p className="text-sm opacity-75">Optional. A verified number can help confirm it&apos;s you later, but it&apos;s never a way to sign in on its own: phone numbers are too easy to take over. Sending a code needs a sign-in within the last five minutes.</p>
    {message && <p role="status" className="text-sm">{message}</p>}
    {!state ? <p role="status">Loading…</p> : <>
      {state.phone && (
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span>{state.phone} <span className="ml-2 rounded-full border border-[var(--hairline)] px-2 py-0.5 text-xs">{state.verified ? "Verified" : "Not verified"}</span></span>
          <button type="button" className={button} disabled={busy} onClick={() => void run({ action: "remove" }, "Phone number removed.")}>Remove</button>
        </div>
      )}
      {state.available && (state.pending ? (
        <form className="flex flex-col gap-3" onSubmit={(event) => { event.preventDefault(); void run({ action: "confirm", code }, "Phone number verified.").then((ok) => { if (ok) setCode(""); }); }}>
          <FormField label={`Code texted to ${state.pending}`} inputMode="numeric" autoComplete="one-time-code" maxLength={7} value={code} onChange={(event) => setCode(event.target.value)} />
          <div className="flex flex-wrap gap-2">
            <button type="submit" className={button} disabled={busy || code.replace(/\s+/g, "").length !== 6}>Verify</button>
          </div>
        </form>
      ) : (!state.verified || !state.phone) && (
        <form className="flex flex-col gap-3" onSubmit={(event) => { event.preventDefault(); void run({ action: "start", phone }, "We've texted you a code."); }}>
          <FormField label={state.phone ? "Verify this number, or enter another" : "Phone number, with country code"} type="tel" autoComplete="tel" placeholder="+91 98765 43210" maxLength={32} value={phone || state.phone || ""} onChange={(event) => setPhone(event.target.value)} />
          <button type="submit" className={`${button} self-start`} disabled={busy || !(phone || state.phone)}>Text me a code</button>
        </form>
      ))}
    </>}
  </section>;
}
