"use client";

import { FormEvent, useState } from "react";
import { FormField, Notice, SubmitButton, TextLink } from "@/components/auth-ui";
import { getCsrf } from "@/lib/auth/csrf-client";

/** Changing the password (or, for an account without one, where to get one). */
export function PasswordForm({ hasPassword, breached }: { hasPassword: boolean; breached: boolean }) {
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);

  async function onChange(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setSaved(false);
    setBusy(true);
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    try {
      const res = await fetch("/api/auth/change-password", {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json", "x-csrf-token": await getCsrf() },
        body: JSON.stringify({ currentPassword: form.get("currentPassword"), newPassword: form.get("newPassword") }),
      });
      const data = (await res.json()) as { message?: string };
      if (!res.ok) {
        setError(data.message ?? "Could not change password");
        return;
      }
      formElement.reset();
      setSaved(true);
      window.setTimeout(() => setSaved(false), 2500);
    } catch {
      setError("Could not change password");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section id="password" aria-labelledby="password-title" className="scroll-mt-8 space-y-4 rounded-2xl border border-[var(--hairline)] p-6">
      <div>
        <h2 id="password-title" className="text-xl font-semibold">Password</h2>
        <p className="mt-1 text-sm text-[var(--muted-foreground)]">Changing it signs you out on your other devices.</p>
      </div>
      {breached ? (
        <p role="alert" className="rounded-xl border border-[var(--hairline)] px-3 py-2 text-sm">
          Your password has appeared in a data breach elsewhere. Change it now.
        </p>
      ) : null}
      {hasPassword ? (
        <form className="flex flex-col gap-4" onSubmit={onChange}>
          <FormField label="Current password" name="currentPassword" type="password" required autoComplete="current-password" />
          <FormField label="New password" name="newPassword" type="password" required autoComplete="new-password" />
          {error ? <Notice tone="error">{error}</Notice> : null}
          {saved ? <Notice tone="success">Password updated. Other sessions were signed out.</Notice> : null}
          <div className="flex flex-wrap items-center gap-4">
            <SubmitButton busy={busy} busyLabel="Updating">Change password</SubmitButton>
            <TextLink href="/forgot-password">Forgot it? Reset by email</TextLink>
          </div>
        </form>
      ) : (
        <p className="text-sm text-[var(--muted-foreground)]">
          This account has no password; it signs in another way. Add one under Ways to sign in above if you&apos;d like one.
        </p>
      )}
    </section>
  );
}
