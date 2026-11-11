"use client";

import { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import { AuthShell } from "@noirly-dev/ui";
import { AuthLogo } from "@/components/AuthLogo";
import { BusyOverlay, Notice, ScreenFallback, SubmitButton, TextLink } from "@/components/auth-ui";
import { getCsrf } from "@/lib/auth/csrf-client";
import { goReturnTo, withReturnTo } from "@/lib/auth/return-to";

function MagicLinkForm() {
  const params = useSearchParams();
  const token = params.get("token") ?? "";
  const returnTo = params.get("return_to");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(token ? null : "This link is missing its code. Open it from the email again.");

  async function signIn() {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/auth/magic-link/verify", {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json", "x-csrf-token": await getCsrf() },
        body: JSON.stringify({ token }),
      });
      const data = (await res.json()) as { redirectTo?: string; error?: string; message?: string };
      if (res.ok) {
        goReturnTo(data.redirectTo ?? returnTo ?? "/account");
        return;
      }
      if (data.error === "mfa_required") {
        window.location.assign(withReturnTo("/mfa", returnTo));
        return;
      }
      setError(data.message || "Sign-in failed");
    } catch {
      setError("Sign-in failed. Try again.");
    }
    setBusy(false);
  }

  return (
    <AuthShell
      logo={<AuthLogo />}
      title="Sign in with your link"
      lead="You asked for a link to sign in to Noirly."
      footer={<TextLink href={withReturnTo("/login", returnTo)}>Back to sign in</TextLink>}
    >
      {busy ? <BusyOverlay label="Signing in" /> : null}
      <div className="flex flex-col gap-4">
        <form className="flex flex-col gap-4" onSubmit={(event) => { event.preventDefault(); void signIn(); }}>
          <SubmitButton busy={busy} busyLabel="Signing in" disabled={!token}>
            Sign in
          </SubmitButton>
        </form>
        {error ? <Notice tone="error">{error}</Notice> : null}
      </div>
    </AuthShell>
  );
}

export default function MagicLinkPage() {
  return (
    <Suspense fallback={<ScreenFallback title="Loading" />}>
      <MagicLinkForm />
    </Suspense>
  );
}
