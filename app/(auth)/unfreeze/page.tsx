"use client";

import { FormEvent, Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import { AuthShell, Button } from "@noirly-dev/ui";
import { AuthLogo } from "@/components/AuthLogo";
import { FormField, Notice, ScreenFallback } from "@/components/auth-ui";
import { securityRequest } from "@/components/security/client";

/**
 * Unfreezing: ask by email; confirm from the emailed link (it unfreezes a day
 * later); or keep it frozen from the link in the "unfreezes tomorrow" email.
 */
function Unfreeze() {
  const params = useSearchParams();
  const token = params.get("token");
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState<{ tone: "success" | "error"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  async function run(body: Record<string, string>, done: (data: { unlockAt?: string }) => string) {
    setBusy(true);
    setMessage(null);
    try {
      const data = await securityRequest<{ unlockAt?: string }>("/api/auth/freeze", body);
      setMessage({ tone: "success", text: done(data) });
    } catch (error) {
      setMessage({ tone: "error", text: error instanceof Error ? error.message : "That didn't work" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell logo={<AuthLogo />} title="Unfreeze your account" lead="Unfreezing takes a day after you confirm by email, so whoever froze it has time to stop a stranger.">
      <div className="flex flex-col gap-4">
        {message ? <Notice tone={message.tone}>{message.text}</Notice> : null}
        {token ? (
          <>
            <Button type="button" disabled={busy} onClick={() => void run({ action: "confirm-unfreeze", token }, (d) => `Confirmed. Your account unfreezes ${d.unlockAt ? new Date(d.unlockAt).toLocaleString() : "tomorrow"}.`)}>Unfreeze my account</Button>
            <button type="button" className="text-sm underline" disabled={busy} onClick={() => void run({ action: "cancel-unfreeze", token }, () => "It stays frozen.")}>No, keep it frozen</button>
          </>
        ) : (
          <form className="flex flex-col gap-3" onSubmit={(e: FormEvent) => { e.preventDefault(); void run({ action: "request-unfreeze", email }, () => "If that account is frozen, we've emailed every address on it a link to confirm."); }}>
            <FormField label="Your account's email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
            <Button type="submit" disabled={busy || !email}>Email me a link</Button>
          </form>
        )}
      </div>
    </AuthShell>
  );
}

export default function UnfreezePage() {
  return <Suspense fallback={<ScreenFallback title="Loading" />}><Unfreeze /></Suspense>;
}
