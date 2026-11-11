"use client";

import { FormEvent, Suspense, useEffect, useMemo, useState } from "react";
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
import { withReturnTo } from "@/lib/auth/return-to";

function maskEmail(email: string): string {
  const normalized = email.trim().toLowerCase();
  const at = normalized.indexOf("@");
  if (at <= 0) return "***";
  return `${normalized.slice(0, 1)}***@${normalized.slice(at + 1)}`;
}

function CheckEmailContent() {
  const params = useSearchParams();
  const emailFromQuery = params.get("email") ?? "";
  const returnTo = params.get("return_to");
  const [email, setEmail] = useState(emailFromQuery);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [cooldown, setCooldown] = useState(0);
  const [sending, setSending] = useState(false);
  const [code, setCode] = useState("");
  const [verifying, setVerifying] = useState(false);
  const [codeResult, setCodeResult] = useState<{ ok: boolean; text: string } | null>(null);

  const masked = useMemo(() => (email ? maskEmail(email) : null), [email]);

  useEffect(() => {
    if (cooldown <= 0) return;
    const id = window.setInterval(() => {
      setCooldown((value) => Math.max(0, value - 1));
    }, 1000);
    return () => window.clearInterval(id);
  }, [cooldown]);

  async function resend(event?: FormEvent) {
    event?.preventDefault();
    setError(null);
    setMessage(null);
    if (!email) {
      setError("Enter the email address you registered with.");
      return;
    }
    if (cooldown > 0 || sending) {
      return;
    }

    setSending(true);
    try {
      const res = await fetch("/api/auth/resend-verification", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const data = (await res.json()) as {
        message?: string;
        cooldownSeconds?: number;
        details?: { retryAfterSeconds?: number };
      };

      if (!res.ok) {
        if (res.status === 429) {
          const wait = data.details?.retryAfterSeconds ?? data.cooldownSeconds ?? 60;
          setCooldown(wait);
          setError(`Resend available in ${wait} seconds`);
          return;
        }
        setError(data.message ?? "Unable to resend verification email");
        return;
      }

      setMessage("Verification email sent. Please check your inbox.");
      setCooldown(data.cooldownSeconds ?? 60);
    } catch {
      setError("Unable to resend verification email");
    } finally {
      setSending(false);
    }
  }

  async function verifyCode(event: FormEvent) {
    event.preventDefault();
    setCodeResult(null);
    if (!email) {
      setCodeResult({ ok: false, text: "Enter the email address you registered with." });
      return;
    }
    setVerifying(true);
    try {
      const res = await fetch("/api/auth/verify-email/code", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, code }),
      });
      const data = (await res.json()) as { message?: string };
      setCodeResult({ ok: res.ok, text: res.ok ? "Your email address is verified. You can sign in now." : (data.message ?? "That code didn't work") });
    } catch {
      setCodeResult({ ok: false, text: "That code didn't work. Try again." });
    } finally {
      setVerifying(false);
    }
  }

  return (
    <AuthShell
      logo={<AuthLogo />}
      title="Check your email"
      lead={
        masked
          ? `We've sent a verification link to ${masked}. Click the button in the email to verify your account.`
          : "We've sent a verification link. Click the button in the email to verify your account."
      }
      footer={
        <TextLink href={withReturnTo("/login", returnTo)}>
          Already verified? Sign in
        </TextLink>
      }
    >
      {sending ? <BusyOverlay label="Sending verification email" /> : null}
      <div className="flex flex-col gap-6">
        <p className="text-xs font-medium uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
          Didn&apos;t receive it?
        </p>
        <form className="flex flex-col gap-4" onSubmit={resend}>
          {!emailFromQuery ? (
            <FormField
              label="Email address"
              type="email"
              placeholder="you@noirly.com"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              required
            />
          ) : null}
          <SubmitButton
            type="submit"
            busy={sending}
            disabled={cooldown > 0}
            busyLabel="Sending"
          >
            {cooldown > 0
              ? `Resend available in ${cooldown}s`
              : "Resend verification email"}
          </SubmitButton>
        </form>
        {message ? <Notice tone="success">{message}</Notice> : null}
        {error ? <Notice tone="error">{error}</Notice> : null}
        <p className="text-xs font-medium uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
          Have the code instead?
        </p>
        <form className="flex flex-col gap-4" onSubmit={verifyCode}>
          <FormField
            label="Code from the email"
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="123 456"
            maxLength={7}
            value={code}
            onChange={(event) => setCode(event.target.value)}
          />
          <SubmitButton type="submit" busy={verifying} busyLabel="Checking" disabled={code.replace(/\s+/g, "").length !== 6}>
            Verify with code
          </SubmitButton>
        </form>
        {codeResult ? <Notice tone={codeResult.ok ? "success" : "error"}>{codeResult.text}</Notice> : null}
      </div>
    </AuthShell>
  );
}

export default function CheckEmailPage() {
  return (
    <Suspense fallback={<ScreenFallback title="Loading" />}>
      <CheckEmailContent />
    </Suspense>
  );
}
