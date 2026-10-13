"use client";

import { FormEvent, Suspense, useEffect, useState, useSyncExternalStore } from "react";
import { useSearchParams } from "next/navigation";
import { AuthShell } from "@noirly-dev/ui";
import { AuthLogo } from "@/components/AuthLogo";
import {
  BusyOverlay,
  FormField,
  GoogleButton,
  Notice,
  ScreenFallback,
  SubmitButton,
  TextLink,
} from "@/components/auth-ui";
import { PasskeySignIn } from "@/components/security/PasskeySignIn";
import { GoogleOneTap } from "@/components/GoogleOneTap";
import { OrDivider } from "@/components/OrDivider";
import { getCsrf } from "@/lib/auth/csrf-client";
import { goReturnTo, isPopupLogin, withPopup, withReturnTo } from "@/lib/auth/return-to";
import { forgetEmail, recentEmailsSnapshot, rememberEmail, serverRecentEmailsSnapshot, subscribeRecentEmails } from "@/lib/auth/recent-emails";

export function LoginForm({
  popup = false,
  currentEmail = null,
  selectAccount = false,
}: {
  popup?: boolean;
  currentEmail?: string | null;
  selectAccount?: boolean;
}) {
  const searchParams = useSearchParams();
  const returnTo = searchParams.get("return_to");
  const compact = popup || isPopupLogin(searchParams.get("popup"));
  const [error, setError] = useState<string | null>(searchParams.get("error"));
  const [unverifiedEmail, setUnverifiedEmail] = useState<string | null>(null);
  const [csrf, setCsrf] = useState("");
  const [googleEnabled, setGoogleEnabled] = useState(false);
  const [googleClientId, setGoogleClientId] = useState<string | null>(null);
  const recentEmails = JSON.parse(useSyncExternalStore(subscribeRecentEmails, recentEmailsSnapshot, serverRecentEmailsSnapshot)) as string[];
  const [email, setEmail] = useState(currentEmail ?? "");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    void getCsrf().then(setCsrf);
    if (currentEmail) rememberEmail(currentEmail);
    void fetch("/api/auth/oauth-providers")
      .then((res) => res.json() as Promise<{ google?: boolean; googleClientId?: string | null }>)
      .then((data) => {
        setGoogleEnabled(Boolean(data.google));
        setGoogleClientId(data.googleClientId ?? null);
      })
      .catch(() => undefined);
  }, [currentEmail]);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setUnverifiedEmail(null);
    setSubmitting(true);
    const form = new FormData(event.currentTarget);
    const submittedEmail = String(form.get("email") ?? email);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        credentials: "include",
        headers: {
          "content-type": "application/json",
          "x-csrf-token": csrf || (await getCsrf()),
        },
        body: JSON.stringify({
          email: submittedEmail,
          password: form.get("password"),
        }),
      });
      if (!res.ok) {
        const data = (await res.json()) as { message?: string; error?: string };
        if (data.error === "mfa_required") {
          window.location.assign(withReturnTo("/mfa", returnTo));
          return;
        }
        if (data.error === "email_not_verified") {
          setUnverifiedEmail(submittedEmail.trim().toLowerCase());
          setError(
            data.message ?? "Please verify your email address before signing in.",
          );
        } else {
          setError(data.message ?? "Login failed");
        }
        setSubmitting(false);
        return;
      }
      rememberEmail(submittedEmail);
      goReturnTo(returnTo ?? "/account");
    } catch {
      setError("Login failed");
      setSubmitting(false);
    }
  }

  const registerHref = withPopup(withReturnTo("/register", returnTo), compact);
  const googleBlock =
    googleEnabled && googleClientId ? (
      <>
        <GoogleOneTap
          clientId={googleClientId}
          returnTo={returnTo}
          popup={compact}
          autoPrompt={!selectAccount}
        />
        <OrDivider />
      </>
    ) : googleEnabled ? (
      <>
        <GoogleButton returnTo={returnTo ?? "/account"} />
        <OrDivider />
      </>
    ) : null;

  const accountsBlock =
    recentEmails.length > 0 || currentEmail ? (
      <div className="flex flex-col gap-2">
        <p className="text-xs font-medium uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
          {selectAccount ? "Choose an account" : "Accounts on this device"}
        </p>
        {currentEmail && selectAccount ? (
          <button
            type="button"
            className="rounded-xl border border-[var(--hairline)] bg-[var(--surface-2)] px-3 py-3 text-left transition-colors hover:bg-[var(--surface)]"
            onClick={() => goReturnTo(returnTo ?? "/account")}
          >
            <span className="block text-[10px] uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
              Continue as
            </span>
            <span className="mt-1 block truncate text-sm">{currentEmail}</span>
          </button>
        ) : null}
        {recentEmails.map((item) => {
          const googleHref = withReturnTo(
            `/api/auth/google?login_hint=${encodeURIComponent(item)}`,
            returnTo,
          );
          const isCurrent = currentEmail === item;
          return (
            <div
              key={item}
              className="flex items-center gap-2 rounded-xl border border-[var(--hairline)] px-3 py-2"
            >
              <button
                type="button"
                className="min-w-0 flex-1 truncate text-left text-sm"
                onClick={() => {
                  if (selectAccount && isCurrent) {
                    goReturnTo(returnTo ?? "/account");
                    return;
                  }
                  setEmail(item);
                }}
              >
                {item}
                {isCurrent ? (
                  <span className="ml-2 text-[10px] uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
                    current
                  </span>
                ) : null}
              </button>
              {googleEnabled ? (
                <a
                  href={googleHref}
                  className="shrink-0 text-[10px] uppercase tracking-[0.12em] text-[var(--muted-foreground)] underline underline-offset-4 hover:text-[var(--foreground)]"
                >
                  Google
                </a>
              ) : null}
              <button
                type="button"
                aria-label={`Remove ${item}`}
                className="shrink-0 text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
                onClick={() => forgetEmail(item)}
              >
                ×
              </button>
            </div>
          );
        })}
        <OrDivider />
      </div>
    ) : null;

  return (
    <AuthShell
      logo={<AuthLogo />}
      title={selectAccount ? "Choose account" : "Sign in to Noirly"}
      lead="Access your Noirly identity across the ecosystem."
      footer={
        <div className="flex flex-wrap items-center justify-center gap-x-4 gap-y-2">
          <TextLink href={withPopup("/forgot-password", compact)}>
            Forgot password?
          </TextLink>
          <TextLink href={registerHref}>No account? Register</TextLink>
        </div>
      }
    >
      {submitting ? <BusyOverlay label="Signing in" /> : null}
      <div className="flex flex-col gap-6">
        {selectAccount ? (
          <>
            {accountsBlock}
            {googleBlock}
          <PasskeySignIn returnTo={returnTo} />
          </>
        ) : (
          <>
            {googleBlock}
          <PasskeySignIn returnTo={returnTo} />
            {accountsBlock}
          </>
        )}
        <form className="flex flex-col gap-4" onSubmit={onSubmit}>
          <FormField
            label="Email"
            name="email"
            type="email"
            placeholder="you@noirly.com"
            required
            autoComplete="username"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
          <FormField
            label="Password"
            name="password"
            type="password"
            placeholder="••••••••••"
            required
            autoComplete="current-password"
          />
          <SubmitButton busy={submitting} busyLabel="Signing in">
            Sign in
          </SubmitButton>
        </form>
        {error ? <Notice tone="error">{error}</Notice> : null}
        {unverifiedEmail ? (
          <TextLink
            href={withPopup(
              withReturnTo(
                `/check-email?email=${encodeURIComponent(unverifiedEmail)}`,
                returnTo,
              ),
              compact,
            )}
          >
            Resend verification email
          </TextLink>
        ) : null}
      </div>
    </AuthShell>
  );
}

export function LoginPageClient({
  popup = false,
  currentEmail = null,
  selectAccount = false,
}: {
  popup?: boolean;
  currentEmail?: string | null;
  selectAccount?: boolean;
}) {
  return (
    <Suspense fallback={<ScreenFallback title="Loading" />}>
      <LoginForm
        popup={popup}
        currentEmail={currentEmail}
        selectAccount={selectAccount}
      />
    </Suspense>
  );
}
