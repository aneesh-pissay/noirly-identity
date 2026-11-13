"use client";

import { FormEvent, useState } from "react";
import { AvatarPicker } from "@/components/AvatarPicker";
import { FormField, Notice, SubmitButton } from "@/components/auth-ui";
import { getCsrf } from "@/lib/auth/csrf-client";
import type { PublicUser } from "@/types";

/** Name, display name, phone and photo: what Noirly apps show for you. */
export function ProfileForm({ initialUser }: { initialUser: PublicUser }) {
  const [user, setUser] = useState(initialUser);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);

  async function onSave(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setSaved(false);
    setBusy(true);
    const form = new FormData(event.currentTarget);
    try {
      const res = await fetch("/api/auth/me", {
        method: "PATCH",
        credentials: "include",
        headers: { "content-type": "application/json", "x-csrf-token": await getCsrf() },
        body: JSON.stringify({
          firstName: form.get("firstName"),
          lastName: form.get("lastName"),
          displayName: form.get("displayName") || undefined,
          phoneNumber: String(form.get("phoneNumber") ?? "").trim() || null,
        }),
      });
      const data = (await res.json()) as { user?: PublicUser; message?: string };
      if (!res.ok || !data.user) {
        setError(data.message ?? "Could not update profile");
        return;
      }
      setUser(data.user);
      setSaved(true);
      window.setTimeout(() => setSaved(false), 2000);
    } catch {
      setError("Could not update profile");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="profile-title" className="space-y-5 rounded-2xl border border-[var(--hairline)] p-6">
      <div>
        <h2 id="profile-title" className="text-xl font-semibold">Name and photo</h2>
        <p className="mt-1 text-sm text-[var(--muted-foreground)]">How you appear in Flow, Ledger and every Noirly app you allow.</p>
      </div>
      <AvatarPicker avatarUrl={user.avatarUrl} name={user.displayName} onChange={(avatarUrl) => setUser((current) => ({ ...current, avatarUrl }))} />
      <form className="flex flex-col gap-4" onSubmit={onSave}>
        <div className="grid gap-4 sm:grid-cols-2">
          <FormField label="First name" name="firstName" defaultValue={user.firstName} required autoComplete="given-name" />
          <FormField label="Last name" name="lastName" defaultValue={user.lastName} required autoComplete="family-name" />
        </div>
        <FormField label="Display name" name="displayName" defaultValue={user.displayName} autoComplete="nickname" />
        <FormField label="Phone" name="phoneNumber" type="tel" defaultValue={user.phoneNumber ?? ""} autoComplete="tel" />
        {error ? <Notice tone="error">{error}</Notice> : null}
        {saved ? <Notice tone="success">Profile saved</Notice> : null}
        <div>
          <SubmitButton busy={busy} busyLabel="Saving">Save profile</SubmitButton>
        </div>
      </form>
    </section>
  );
}
