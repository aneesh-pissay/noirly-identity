"use client";

import { FormEvent, Suspense, useEffect, useState } from "react";
import { solveSignupChallenge } from "@/lib/auth/solve-challenge";
import { useRouter, useSearchParams } from "next/navigation";
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
import { getCsrf } from "@/lib/auth/csrf-client";
import { withPopup, withReturnTo } from "@/lib/auth/return-to";

function RegisterForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const returnTo = searchParams.get("return_to");
  const compact = searchParams.get("popup") === "1";
  const [error, setError] = useState<string | null>(null);
  const [csrf, setCsrf] = useState("");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    void getCsrf().then(setCsrf);
  }, []);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    const form = new FormData(event.currentTarget);
    const email = String(form.get("email") ?? "");
    try {
      // A moment's work first, so scripts can't make accounts by the thousand.
      const { challenge, bits } = (await (await fetch("/api/auth/register/challenge", { cache: "no-store" })).json()) as { challenge: string; bits: number };
      const solution = await solveSignupChallenge(challenge, bits);
      const res = await fetch("/api/auth/register", {
        method: "POST",
        credentials: "include",
        headers: {
          "content-type": "application/json",
          "x-csrf-token": csrf || (await getCsrf()),
        },
        body: JSON.stringify({
          email,
          password: form.get("password"),
          firstName: form.get("firstName"),
          lastName: form.get("lastName"),
          challenge,
          solution,
        }),
      });
      if (!res.ok) {
        const data = (await res.json()) as { message?: string };
        setError(data.message ?? "Registration failed");
        setSubmitting(false);
        return;
      }
      router.push(
        withReturnTo(
          `/check-email?email=${encodeURIComponent(email.trim().toLowerCase())}`,
          returnTo,
        ),
      );
    } catch {
      setError("Registration failed");
      setSubmitting(false);
    }
  }

  const loginHref = withPopup(withReturnTo("/login", returnTo), compact);

  return (
    <AuthShell
      logo={<AuthLogo />}
      title="Create account"
      lead="One Noirly identity across Flow, CRM, Docs, and the rest of the ecosystem."
      footer={<TextLink href={loginHref}>Already have an account? Sign in</TextLink>}
    >
      {submitting ? <BusyOverlay label="Creating account" /> : null}
      <div className="flex flex-col gap-6">
        <form className="flex flex-col gap-4" onSubmit={onSubmit}>
          <FormField
            label="First name"
            name="firstName"
            placeholder="Ada"
            required
            autoComplete="given-name"
          />
          <FormField
            label="Last name"
            name="lastName"
            placeholder="Lovelace"
            required
            autoComplete="family-name"
          />
          <FormField
            label="Email"
            name="email"
            type="email"
            placeholder="you@noirly.com"
            required
            autoComplete="email"
          />
          <FormField
            label="Password"
            name="password"
            type="password"
            placeholder="••••••••••"
            required
            autoComplete="new-password"
          />
          <SubmitButton busy={submitting} busyLabel="Creating account">
            Register
          </SubmitButton>
        </form>
        {error ? <Notice tone="error">{error}</Notice> : null}
      </div>
    </AuthShell>
  );
}

export default function RegisterPage() {
  return (
    <Suspense fallback={<ScreenFallback title="Loading" />}>
      <RegisterForm />
    </Suspense>
  );
}
