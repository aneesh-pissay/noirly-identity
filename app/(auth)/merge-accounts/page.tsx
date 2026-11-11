"use client";

import { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import { AuthShell } from "@noirly-dev/ui";
import { AuthLogo } from "@/components/AuthLogo";
import { BusyOverlay, Notice, ScreenFallback, SubmitButton, TextLink } from "@/components/auth-ui";

type Result = { keeperEmail: string | null; completeWithinHours: number };

function ConfirmForm() {
  const token = useSearchParams().get("token") ?? "";
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState<string | null>(token ? null : "This link is missing its code. Open it from the email again.");

  async function confirm() {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/auth/merge/confirm", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token }) });
      const data = (await res.json()) as Result & { message?: string };
      if (res.ok) setResult(data);
      else setError(data.message || "The merge couldn't be confirmed");
    } catch {
      setError("The merge couldn't be confirmed. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell
      logo={<AuthLogo />}
      title={result ? "Confirmed" : "Merge your accounts"}
      lead={result ? undefined : "Another Noirly account asked to take this one in. Confirm only if both are yours."}
      footer={<TextLink href="/account">Go to your account</TextLink>}
    >
      {busy ? <BusyOverlay label="Confirming" /> : null}
      <div className="flex flex-col gap-4">
        {result ? (
          <Notice tone="success">
            Now sign in to the account you&apos;re keeping{result.keeperEmail ? ` (${result.keeperEmail})` : ""}, review what moves across, and complete the merge from its account page within {result.completeWithinHours} hours. Nothing has changed yet.
          </Notice>
        ) : (
          <form className="flex flex-col gap-4" onSubmit={(event) => { event.preventDefault(); void confirm(); }}>
            <p className="text-sm">Once merged, this account&apos;s ways to sign in, email addresses and spaces move to the other account, and this one is closed. You&apos;ll see exactly what moves before anything happens.</p>
            <SubmitButton busy={busy} busyLabel="Confirming" disabled={!token}>
              Yes, both accounts are mine
            </SubmitButton>
          </form>
        )}
        {error ? <Notice tone="error">{error}</Notice> : null}
      </div>
    </AuthShell>
  );
}

export default function MergeAccountsPage() {
  return (
    <Suspense fallback={<ScreenFallback title="Loading" />}>
      <ConfirmForm />
    </Suspense>
  );
}
