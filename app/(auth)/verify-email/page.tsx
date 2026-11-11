"use client";

import { Suspense, useEffect, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import { AuthShell, Button } from "@noirly-dev/ui";
import { AuthLogo } from "@/components/AuthLogo";
import { ScreenFallback, TextLink } from "@/components/auth-ui";
import { readOauthReturnCookie, sanitizeReturnTo } from "@/lib/auth/return-to";

type VerifyStatus =
  | "loading"
  | "verified"
  | "already_verified"
  | "invalid"
  | "expired"
  | "used"
  | "missing";

const copy: Record<
  Exclude<VerifyStatus, "loading">,
  { title: string; body: string; cta: string; href: string }
> = {
  verified: {
    title: "Email verified",
    body: "Your email address has been verified.",
    cta: "Continue to Noirly",
    href: "/login",
  },
  already_verified: {
    title: "Already verified",
    body: "Your email address has already been verified.",
    cta: "Continue to Noirly",
    href: "/login",
  },
  expired: {
    title: "Link expired",
    body: "This verification link has expired.",
    cta: "Send a new verification email",
    href: "/check-email",
  },
  invalid: {
    title: "Link invalid",
    body: "This verification link is invalid or has already been used.",
    cta: "Send a new verification email",
    href: "/check-email",
  },
  used: {
    title: "Link used",
    body: "This verification link has already been used.",
    cta: "Send a new verification email",
    href: "/check-email",
  },
  missing: {
    title: "Link missing",
    body: "This verification link is invalid or has already been used.",
    cta: "Send a new verification email",
    href: "/check-email",
  },
};

function VerifyContent() {
  const params = useSearchParams();
  const token = params.get("token");
  const [status, setStatus] = useState<VerifyStatus>(token ? "loading" : "missing");
  const started = useRef(false);
  const resumeTo =
    sanitizeReturnTo(params.get("return_to")) ?? readOauthReturnCookie();

  useEffect(() => {
    if (!token || started.current) {
      return;
    }
    started.current = true;

    void (async () => {
      try {
        const res = await fetch(
          `/api/auth/verify-email?token=${encodeURIComponent(token)}`,
          { method: "GET", credentials: "include" },
        );
        const data = (await res.json()) as { status?: VerifyStatus };
        if (
          data.status === "verified" ||
          data.status === "already_verified" ||
          data.status === "expired" ||
          data.status === "used" ||
          data.status === "invalid"
        ) {
          setStatus(data.status);
          return;
        }
        setStatus(res.ok ? "verified" : "invalid");
      } catch {
        setStatus("invalid");
      }
    })();
  }, [token]);

  useEffect(() => {
    if (
      (status === "verified" || status === "already_verified") &&
      resumeTo
    ) {
      window.location.assign(resumeTo);
    }
  }, [status, resumeTo]);

  if (status === "loading") {
    return (
      <AuthShell logo={<AuthLogo />} title="Verifying your email" lead="Please wait.">
        <p className="text-center text-sm text-[var(--muted-foreground)]">
          Confirming your verification link…
        </p>
      </AuthShell>
    );
  }

  const view = copy[status];
  const continueHref =
    (status === "verified" || status === "already_verified") && resumeTo
      ? resumeTo
      : view.href;

  return (
    <AuthShell
      logo={<AuthLogo />}
      title={view.title}
      lead={
        continueHref !== view.href
          ? `${view.body} Continue to return to the app that sent you here.`
          : view.body
      }
      footer={<TextLink href="/login">Sign in</TextLink>}
    >
      <div className="flex flex-wrap gap-3">
        <Button asChild>
          <a href={continueHref}>
            {continueHref !== view.href ? "Continue to app" : view.cta}
          </a>
        </Button>
        <Button variant="secondary" asChild>
          <a href="/login">Sign in</a>
        </Button>
      </div>
    </AuthShell>
  );
}

export default function VerifyEmailPage() {
  return (
    <Suspense fallback={<ScreenFallback title="Verifying your email" />}>
      <VerifyContent />
    </Suspense>
  );
}
