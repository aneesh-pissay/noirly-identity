"use client";

import { FormEvent, useState } from "react";
import { Button } from "@noirly-dev/ui";
import { BusyOverlay, FormField, Notice } from "@/components/auth-ui";
import { getCsrf } from "@/lib/auth/csrf-client";

/**
 * Confirms and deletes the signed-in account. Accounts with a password confirm
 * with it; Google-only accounts type their email instead.
 */
export function DeleteAccountForm({ email, hasPassword }: { email: string; hasPassword: boolean }) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [understood, setUnderstood] = useState(false);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!understood) return;
    setError(null);
    setBusy(true);
    const form = new FormData(event.currentTarget);
    try {
      const res = await fetch("/api/auth/delete-account", {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json", "x-csrf-token": await getCsrf() },
        body: JSON.stringify(
          hasPassword
            ? { password: String(form.get("password") ?? "") }
            : { confirmEmail: String(form.get("confirmEmail") ?? "") },
        ),
      });
      const data = (await res.json().catch(() => ({}))) as { message?: string };
      if (!res.ok) {
        setError(data.message ?? "Could not delete the account");
        return;
      }
      setDone(true);
    } catch {
      setError("Could not delete the account. Check your connection and try again.");
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <Notice tone="success">
        Your account and its data have been deleted, and you have been signed out everywhere. Thank you for using Noirly.
      </Notice>
    );
  }

  return (
    <form className="flex max-w-md flex-col gap-4" onSubmit={onSubmit}>
      {busy ? <BusyOverlay label="Deleting account" /> : null}
      <p>
        Signed in as <strong>{email}</strong>.
      </p>
      {hasPassword ? (
        <FormField label="Password" name="password" type="password" required autoComplete="current-password" />
      ) : (
        <FormField
          label={`Type ${email} to confirm`}
          name="confirmEmail"
          type="email"
          required
          autoComplete="off"
          placeholder={email}
        />
      )}
      <label className="flex items-start gap-3 text-sm text-[var(--muted-foreground)]">
        <input
          type="checkbox"
          className="mt-1 size-4 accent-[var(--destructive)]"
          checked={understood}
          onChange={(e) => setUnderstood(e.target.checked)}
        />
        <span>I understand this permanently deletes my account and my Noirly Flow data.</span>
      </label>
      {error ? <Notice tone="error">{error}</Notice> : null}
      <div>
        <Button type="submit" variant="destructive" disabled={!understood || busy}>
          Delete my account
        </Button>
      </div>
    </form>
  );
}
