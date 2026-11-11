"use client";

import { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import { AuthShell } from "@noirly-dev/ui";
import { AuthLogo } from "@/components/AuthLogo";
import { BusyOverlay, Notice, ScreenFallback, SubmitButton, TextLink } from "@/components/auth-ui";

type Result = { email: string; passwordResetSent: boolean };

function UndoForm() {
  const token = useSearchParams().get("token") ?? "";
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState<string | null>(token ? null : "This link is missing its code. Open it from the email again.");

  async function undo() {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/auth/email-change/undo", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token }),
      });
      const data = (await res.json()) as Result & { message?: string };
      if (res.ok) setResult(data);
      else setError(data.message || "The change couldn't be undone");
    } catch {
      setError("The change couldn't be undone. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell
      logo={<AuthLogo />}
      title={result ? "Change undone" : "Undo email change"}
      lead={result ? undefined : "If you didn't change your Noirly account's primary email address, put the old one back."}
      footer={<TextLink href="/login">{result ? "Continue to sign in" : "Back to sign in"}</TextLink>}
    >
      {busy ? <BusyOverlay label="Undoing the change" /> : null}
      <div className="flex flex-col gap-4">
        {result ? (
          <Notice tone="success">
            {result.email} is your primary address again. The address that replaced it was removed, and every device and app was signed out.
            {result.passwordResetSent ? " We've sent a password reset link to it: choose a new password before you sign in." : " Sign in again to check your account's security activity."}
          </Notice>
        ) : (
          <form className="flex flex-col gap-4" onSubmit={(event) => { event.preventDefault(); void undo(); }}>
            <p className="text-sm">This puts your old address back as primary, removes the address that replaced it, and signs out every device and app, yours included.</p>
            <SubmitButton busy={busy} busyLabel="Undoing" disabled={!token}>
              This wasn&apos;t me — undo it
            </SubmitButton>
          </form>
        )}
        {error ? <Notice tone="error">{error}</Notice> : null}
      </div>
    </AuthShell>
  );
}

export default function UndoEmailChangePage() {
  return (
    <Suspense fallback={<ScreenFallback title="Loading" />}>
      <UndoForm />
    </Suspense>
  );
}
