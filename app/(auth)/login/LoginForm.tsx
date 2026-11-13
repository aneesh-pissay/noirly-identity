"use client";

import { FormEvent, Suspense, useEffect, useState, useSyncExternalStore } from "react";
import { useSearchParams } from "next/navigation";
import { AuthShell } from "@noirly-dev/ui";
import { AuthLogo } from "@/components/AuthLogo";
import {
  BusyOverlay,
  FormField,
  Notice,
  ScreenFallback,
  SubmitButton,
  TextLink,
} from "@/components/auth-ui";
import { PasskeySignIn } from "@/components/security/PasskeySignIn";
import { OrDivider } from "@/components/OrDivider";
import { getCsrf } from "@/lib/auth/csrf-client";
import type { SignInOptions } from "@/lib/auth/discovery";
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
  const recentEmails = JSON.parse(useSyncExternalStore(subscribeRecentEmails, recentEmailsSnapshot, serverRecentEmailsSnapshot)) as string[];
  const [email, setEmail] = useState(currentEmail ?? "");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    void getCsrf().then(setCsrf);
    if (currentEmail) rememberEmail(currentEmail);
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

  const [linkSentTo, setLinkSentTo] = useState<string | null>(null);
  const [options, setOptions] = useState<SignInOptions | null>(null);

  /** Step one of signing in: which ways this address can use. */
  async function discover() {
    const address = email.trim();
    if (!address) return;
    setError(null);
    setSubmitting(true);
    try {
      const res = await fetch("/api/auth/discover", {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json", "x-csrf-token": csrf || (await getCsrf()) },
        body: JSON.stringify({ email: address }),
      });
      const data = (await res.json()) as SignInOptions & { message?: string };
      if (!res.ok) setError(data.message ?? "Couldn't continue");
      // An organization that requires its own sign-in: straight there.
      // Break-glass accounts (lib/federation/enforcement.ts) come in by /login?break_glass=1, for when the IdP is down.
      else if (data.sso?.required && searchParams.get("break_glass") === "1") setOptions({ ...data, password: true })
      // A full navigation (an API route that redirects off-site to the IdP), so an absolute URL.
      else if (data.sso?.required) window.location.assign(new URL(`${data.sso.startUrl}&return_to=${encodeURIComponent(returnTo ?? "/account")}`, window.location.origin).toString());
      else setOptions(data);
    } catch {
      setError("Couldn't continue");
    } finally {
      setSubmitting(false);
    }
  }
  const [code, setCode] = useState("");

  /** The code from the same email, typed here instead of opening the link. */
  async function signInWithCode() {
    if (!linkSentTo) return;
    setError(null);
    setSubmitting(true);
    try {
      const res = await fetch("/api/auth/magic-link/code", {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json", "x-csrf-token": csrf || (await getCsrf()) },
        body: JSON.stringify({ email: linkSentTo, code }),
      });
      const data = (await res.json()) as { redirectTo?: string; error?: string; message?: string };
      if (res.ok) {
        rememberEmail(linkSentTo);
        goReturnTo(data.redirectTo ?? returnTo ?? "/account");
        return;
      }
      if (data.error === "mfa_required") {
        window.location.assign(withReturnTo("/mfa", returnTo));
        return;
      }
      setError(data.message ?? "Sign-in failed");
    } catch {
      setError("Sign-in failed");
    }
    setSubmitting(false);
  }

  /** Emails a sign-in link instead of using a password. */
  async function sendLink() {
    const address = email.trim();
    if (!address) {
      setError("Enter your email address first");
      return;
    }
    setError(null);
    setLinkSentTo(null);
    setSubmitting(true);
    try {
      const res = await fetch("/api/auth/magic-link", {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json", "x-csrf-token": csrf || (await getCsrf()) },
        body: JSON.stringify({ email: address, return_to: returnTo }),
      });
      const data = (await res.json()) as { message?: string };
      if (!res.ok) setError(data.message ?? "Couldn't send a link");
      else setLinkSentTo(address);
    } catch {
      setError("Couldn't send a link");
    } finally {
      setSubmitting(false);
    }
  }

  const registerHref = withPopup(withReturnTo("/register", returnTo), compact);
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
                  setOptions(null);
                }}
              >
                {item}
                {isCurrent ? (
                  <span className="ml-2 text-[10px] uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
                    current
                  </span>
                ) : null}
              </button>
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
            <PasskeySignIn returnTo={returnTo} />
          </>
        ) : (
          <>
            <PasskeySignIn returnTo={returnTo} />
            {accountsBlock}
          </>
        )}
        {!options ? (
          // Step one: the address, then the ways it can sign in.
          <form className="flex flex-col gap-4" onSubmit={(event) => { event.preventDefault(); void discover(); }}>
            <FormField
              label="Email"
              name="email"
              type="email"
              placeholder="you@noirly.com"
              required
              autoComplete="username webauthn"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
            <SubmitButton busy={submitting} busyLabel="Checking">
              Continue
            </SubmitButton>
          </form>
        ) : (
          <div className="flex flex-col gap-4">
            <div className="flex items-center justify-between gap-3 rounded-xl border border-[var(--hairline)] px-3 py-2 text-sm">
              <span className="min-w-0 truncate">{options.email}</span>
              <button type="button" className="shrink-0 text-xs text-[var(--muted-foreground)] underline underline-offset-4 hover:text-[var(--foreground)]" onClick={() => { setOptions(null); setLinkSentTo(null); setError(null); }}>
                Use another email
              </button>
            </div>
            {options.sso ? (
              <a className="inline-flex h-11 items-center justify-center rounded-xl border border-[var(--hairline)] px-4 text-sm font-medium hover:bg-[var(--surface-muted,transparent)]" href={`${options.sso.startUrl}&return_to=${encodeURIComponent(returnTo ?? "/account")}`}>
                Sign in with {options.sso.name}
              </a>
            ) : null}
            {options.passkey ? <p className="text-sm text-[var(--muted-foreground)]">This account has a passkey: use the passkey sign-in above.</p> : null}
            {options.password ? (
              <form className="flex flex-col gap-4" onSubmit={onSubmit}>
                {/* For password managers: the address this password belongs to. */}
                <input type="email" name="email" value={options.email} autoComplete="username" readOnly hidden />
                <FormField
                  label="Password"
                  name="password"
                  type="password"
                  placeholder="••••••••••"
                  required
                  autoFocus
                  autoComplete="current-password"
                />
                <SubmitButton busy={submitting} busyLabel="Signing in">
                  Sign in
                </SubmitButton>
              </form>
            ) : null}
            {options.emailLink ? (
              <button
                type="button"
                disabled={submitting}
                onClick={() => void sendLink()}
                className="text-sm text-[var(--muted-foreground)] underline underline-offset-4 hover:text-[var(--foreground)] disabled:opacity-50"
              >
                {options.password ? "Email me a sign-in link instead" : "Email me a sign-in link"}
              </button>
            ) : null}
          </div>
        )}
        {linkSentTo ? (
          <>
            <Notice tone="success">
              If {linkSentTo} has a Noirly account, we&apos;ve sent it a sign-in link and code. Open the link in this browser, or type the code here, within 15 minutes.
            </Notice>
            <form className="flex flex-col gap-3" onSubmit={(event) => { event.preventDefault(); void signInWithCode(); }}>
              <FormField
                label="Code from the email"
                name="code"
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="123 456"
                maxLength={7}
                value={code}
                onChange={(event) => setCode(event.target.value)}
              />
              <SubmitButton busy={submitting} busyLabel="Signing in" disabled={code.replace(/\s+/g, "").length !== 6}>
                Sign in with code
              </SubmitButton>
            </form>
          </>
        ) : null}
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
