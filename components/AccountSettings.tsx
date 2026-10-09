"use client";

import { FormEvent, useEffect, useState } from "react";
import { AuthShell } from "@noirly-dev/ui";
import { AuthLogo } from "@/components/AuthLogo";
import {
  BusyOverlay,
  FormField,
  Notice,
  SubmitButton,
  TextLink,
} from "@/components/auth-ui";
import { getCsrf } from "@/lib/auth/csrf-client";
import type { PublicUser } from "@/types";

type Props = {
  initialUser: PublicUser;
};

export function AccountSettings({ initialUser }: Props) {
  const [user, setUser] = useState(initialUser);
  const [csrf, setCsrf] = useState("");
  const [profileError, setProfileError] = useState<string | null>(null);
  const [profileSaved, setProfileSaved] = useState(false);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [passwordSaved, setPasswordSaved] = useState(false);
  const [busy, setBusy] = useState<"profile" | "password" | "logout" | null>(
    null,
  );

  useEffect(() => {
    void getCsrf().then(setCsrf);
  }, []);

  async function onSaveProfile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setProfileError(null);
    setProfileSaved(false);
    setBusy("profile");
    const form = new FormData(event.currentTarget);
    try {
      const res = await fetch("/api/auth/me", {
        method: "PATCH",
        credentials: "include",
        headers: {
          "content-type": "application/json",
          "x-csrf-token": csrf || (await getCsrf()),
        },
        body: JSON.stringify({
          firstName: form.get("firstName"),
          lastName: form.get("lastName"),
          displayName: form.get("displayName") || undefined,
          phoneNumber: String(form.get("phoneNumber") ?? "").trim() || null,
        }),
      });
      const data = (await res.json()) as {
        user?: PublicUser;
        message?: string;
      };
      if (!res.ok || !data.user) {
        setProfileError(data.message ?? "Could not update profile");
        return;
      }
      setUser(data.user);
      setProfileSaved(true);
      window.setTimeout(() => setProfileSaved(false), 2000);
    } catch {
      setProfileError("Could not update profile");
    } finally {
      setBusy(null);
    }
  }

  async function onChangePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPasswordError(null);
    setPasswordSaved(false);
    setBusy("password");
    const form = new FormData(event.currentTarget);
    try {
      const res = await fetch("/api/auth/change-password", {
        method: "POST",
        credentials: "include",
        headers: {
          "content-type": "application/json",
          "x-csrf-token": csrf || (await getCsrf()),
        },
        body: JSON.stringify({
          currentPassword: form.get("currentPassword"),
          newPassword: form.get("newPassword"),
        }),
      });
      const data = (await res.json()) as { message?: string };
      if (!res.ok) {
        setPasswordError(data.message ?? "Could not change password");
        return;
      }
      event.currentTarget.reset();
      setPasswordSaved(true);
      window.setTimeout(() => setPasswordSaved(false), 2500);
    } catch {
      setPasswordError("Could not change password");
    } finally {
      setBusy(null);
    }
  }

  async function onLogout() {
    setBusy("logout");
    try {
      await fetch("/api/auth/logout", {
        method: "POST",
        credentials: "include",
        headers: { "x-csrf-token": csrf || (await getCsrf()) },
      });
    } finally {
      window.location.assign("/login");
    }
  }

  return (
    <>
      {busy ? (
        <BusyOverlay
          label={
            busy === "logout"
              ? "Signing out"
              : busy === "password"
                ? "Updating password"
                : "Saving profile"
          }
        />
      ) : null}
      <AuthShell
        logo={<AuthLogo />}
        title="Identity"
        lead="Name, email, and password for every Noirly product."
        size="lg"
        align="top"
        className="py-8"
        footer={
          <div className="flex flex-wrap items-center justify-center gap-4">
            {user.roles.includes("admin") ? (
              <TextLink href="/clients">OAuth clients</TextLink>
            ) : null}
            <button
              type="button"
              onClick={() => void onLogout()}
              className="text-sm text-[var(--muted-foreground)] underline underline-offset-4 hover:text-[var(--foreground)]"
            >
              Sign out
            </button>
          </div>
        }
      >
        <div className="mb-8 space-y-3 rounded-xl border border-[var(--hairline)] bg-[var(--surface-2)] p-4 text-xs text-[var(--muted-foreground)]">
          <div className="flex justify-between gap-4 border-b border-[var(--hairline)] pb-3">
            <span>Email</span>
            <span className="text-[var(--foreground)]">{user.email}</span>
          </div>
          <div className="flex justify-between gap-4 border-b border-[var(--hairline)] pb-3">
            <span>Verified</span>
            <span className="text-[var(--foreground)]">
              {user.emailVerified ? "Yes" : "Pending"}
            </span>
          </div>
          <div className="flex justify-between gap-4 border-b border-[var(--hairline)] pb-3">
            <span>Display</span>
            <span className="text-[var(--foreground)]">{user.displayName || "—"}</span>
          </div>
          <div className="flex justify-between gap-4">
            <span>Password</span>
            <span className="text-[var(--foreground)]">
              {user.hasPassword ? "Set" : "Google only"}
            </span>
          </div>
        </div>

        <div className="flex flex-col gap-10">
          <form className="flex flex-col gap-4" onSubmit={onSaveProfile}>
            <div>
              <p className="text-xs font-medium uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
                Profile
              </p>
              <h2 className="mt-2 font-display text-xl font-semibold tracking-tight">
                Edit details
              </h2>
            </div>
            <FormField
              label="First name"
              name="firstName"
              defaultValue={user.firstName}
              required
              autoComplete="given-name"
            />
            <FormField
              label="Last name"
              name="lastName"
              defaultValue={user.lastName}
              required
              autoComplete="family-name"
            />
            <FormField
              label="Display name"
              name="displayName"
              defaultValue={user.displayName}
              autoComplete="nickname"
            />
            <FormField
              label="Phone"
              name="phoneNumber"
              type="tel"
              defaultValue={user.phoneNumber ?? ""}
              autoComplete="tel"
            />
            {profileError ? <Notice tone="error">{profileError}</Notice> : null}
            {profileSaved ? <Notice tone="success">Profile saved</Notice> : null}
            <SubmitButton busy={busy === "profile"} busyLabel="Saving">
              Save profile
            </SubmitButton>
          </form>

          <div className="border-t border-[var(--hairline)] pt-8">
            <p className="text-xs font-medium uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
              Security
            </p>
            <h2 className="mt-2 font-display text-xl font-semibold tracking-tight">
              Password
            </h2>

            {user.hasPassword ? (
              <form
                className="mt-5 flex flex-col gap-4"
                onSubmit={onChangePassword}
              >
                <FormField
                  label="Current password"
                  name="currentPassword"
                  type="password"
                  required
                  autoComplete="current-password"
                />
                <FormField
                  label="New password"
                  name="newPassword"
                  type="password"
                  required
                  autoComplete="new-password"
                />
                {passwordError ? <Notice tone="error">{passwordError}</Notice> : null}
                {passwordSaved ? (
                  <Notice tone="success">
                    Password updated. Other sessions were signed out.
                  </Notice>
                ) : null}
                <SubmitButton busy={busy === "password"} busyLabel="Updating">
                  Change password
                </SubmitButton>
                <TextLink href="/forgot-password">
                  Forgot password? Reset by email
                </TextLink>
              </form>
            ) : (
              <div className="mt-5 space-y-4">
                <p className="text-sm text-[var(--muted-foreground)]">
                  This account signs in with Google and has no password yet. Use
                  email reset if you want to add one.
                </p>
                <TextLink href="/forgot-password">
                  Reset password by email
                </TextLink>
              </div>
            )}
          </div>

          <div className="border-t border-[var(--hairline)] pt-8">
            <p className="text-xs font-medium uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
              Privacy
            </p>
            <h2 className="mt-2 font-display text-xl font-semibold tracking-tight">
              Your data
            </h2>
            <p className="mt-3 text-sm text-[var(--muted-foreground)]">
              Read what Noirly keeps and why, or delete your account and its
              Noirly Flow data for good.
            </p>
            <div className="mt-4 flex flex-wrap gap-x-6 gap-y-2">
              <TextLink href="/privacy">Privacy policy</TextLink>
              <TextLink href="/delete-account" className="text-red-400 hover:text-red-300">
                Delete account
              </TextLink>
            </div>
          </div>
        </div>
      </AuthShell>
    </>
  );
}
