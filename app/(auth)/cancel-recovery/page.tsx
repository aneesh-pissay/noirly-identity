"use client";

import { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import { AuthShell } from "@noirly-dev/ui";
import { AuthLogo } from "@/components/AuthLogo";
import { BusyOverlay, Notice, ScreenFallback, SubmitButton, TextLink } from "@/components/auth-ui";

function CancelForm() {
  const token = useSearchParams().get("token") ?? "";
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(token ? null : "This link is missing its code. Open it from the email again.");

  async function cancel() {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/auth/recovery/cancel", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token }) });
      const data = (await res.json()) as { message?: string };
      if (res.ok) setDone(true);
      else setError(data.message || "It couldn't be cancelled");
    } catch {
      setError("It couldn't be cancelled. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell
      logo={<AuthLogo />}
      title={done ? "Cancelled" : "Keep your second step"}
      lead={done ? undefined : "Someone asked to remove your account's second sign-in step. If it wasn't you, stop it here."}
      footer={<TextLink href="/forgot-password">Reset your password</TextLink>}
    >
      {busy ? <BusyOverlay label="Cancelling" /> : null}
      <div className="flex flex-col gap-4">
        {done ? (
          <Notice tone="success">Cancelled: your second steps stay as they are. Whoever asked knows your password, so reset it now.</Notice>
        ) : (
          <form className="flex flex-col gap-4" onSubmit={(event) => { event.preventDefault(); void cancel(); }}>
            <SubmitButton busy={busy} busyLabel="Cancelling" disabled={!token}>This wasn&apos;t me — cancel it</SubmitButton>
          </form>
        )}
        {error ? <Notice tone="error">{error}</Notice> : null}
      </div>
    </AuthShell>
  );
}

export default function CancelRecoveryPage() {
  return (
    <Suspense fallback={<ScreenFallback title="Loading" />}>
      <CancelForm />
    </Suspense>
  );
}
