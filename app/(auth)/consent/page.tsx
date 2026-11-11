"use client";

import { FormEvent, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { AuthShell, Button } from "@noirly-dev/ui";
import { AuthLogo } from "@/components/AuthLogo";
import { BusyOverlay, Notice, ScreenFallback } from "@/components/auth-ui";
import { getCsrf } from "@/lib/auth/csrf-client";

function ConsentForm() {
  const params = useSearchParams();
  const [csrf, setCsrf] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"approve" | "deny" | null>(null);
  const clientId = params.get("client_id") ?? "unknown-client";
  const redirectUri = params.get("redirect_uri") ?? "";
  const scopes = useMemo(
    () =>
      (params.get("scope") ?? "")
        .split(/\s+/)
        .map((scope) => scope.trim())
        .filter(Boolean),
    [params],
  );

  useEffect(() => {
    void getCsrf().then(setCsrf);
  }, []);

  // The app's name and what each scope means, from Identity (not the address bar).
  const [described, setDescribed] = useState<{ app: string; canSee: string[] } | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    const query = new URLSearchParams();
    for (const key of ["client_id", "redirect_uri", "scope", "resource"]) {
      const value = params.get(key);
      if (value) query.set(key, value);
    }
    void fetch(`/api/oauth/consent/describe?${query}`, { cache: "no-store", signal: controller.signal })
      .then(async (res) => (res.ok ? ((await res.json()) as { app: string; canSee: string[] }) : null))
      .then((data) => { if (data) setDescribed(data); })
      .catch(() => undefined);
    return () => controller.abort();
  }, [params]);

  async function decide(decision: "approve" | "deny") {
    setError(null);
    setBusy(decision);
    try {
      const res = await fetch("/api/oauth/consent", {
        method: "POST",
        credentials: "include",
        headers: {
          "content-type": "application/json",
          "x-csrf-token": csrf || (await getCsrf()),
        },
        body: JSON.stringify({
          client_id: params.get("client_id"),
          redirect_uri: params.get("redirect_uri"),
          scope: params.get("scope"),
          state: params.get("state") || undefined,
          code_challenge: params.get("code_challenge") || undefined,
          code_challenge_method: params.get("code_challenge_method") || undefined,
          nonce: params.get("nonce") || undefined,
          resource: params.get("resource") || undefined,
          organization: params.get("organization") || undefined,
          decision,
        }),
        redirect: "manual",
      });

      if (res.status >= 300 && res.status < 400) {
        const location = res.headers.get("location");
        if (location) {
          window.location.href = location;
          return;
        }
      }

      if (!res.ok) {
        const data = (await res.json().catch(() => ({}))) as {
          message?: string;
          error_description?: string;
        };
        setError(data.error_description || data.message || "Consent failed");
        setBusy(null);
      }
    } catch {
      setError("Consent failed");
      setBusy(null);
    }
  }

  async function onApprove(event: FormEvent) {
    event.preventDefault();
    await decide("approve");
  }

  return (
    <AuthShell
      title="Authorize application"
      lead={`${described?.app ?? clientId} requests access to your Noirly Identity account.`}
      logo={<AuthLogo />}
    >
      {busy ? (
        <BusyOverlay
          label={busy === "approve" ? "Allowing access" : "Denying access"}
        />
      ) : null}
      <div className="flex flex-col gap-6">
        <p className="text-[10px] uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
          It will be able to see and do
        </p>
        <ul aria-label="What the app is asking for" className="flex flex-col divide-y divide-[var(--hairline)] rounded-xl border border-[var(--hairline)]">
          {described
            ? described.canSee.map((line) => (
                <li key={line} className="px-4 py-3 text-sm">
                  {line}
                </li>
              ))
            : (scopes.length ? scopes : ["openid"]).map((scope) => (
                <li key={scope} className="px-4 py-3 font-mono text-sm uppercase tracking-[0.08em]">
                  {scope}
                </li>
              ))}
        </ul>
        <form className="flex flex-col gap-3 sm:flex-row" onSubmit={onApprove}>
          <Button
            className="flex-1"
            type="submit"
            disabled={busy !== null}
            aria-busy={busy === "approve"}
          >
            {busy === "approve" ? "Allowing…" : "Allow"}
          </Button>
          <Button
            className="flex-1"
            type="button"
            variant="secondary"
            disabled={busy !== null}
            aria-busy={busy === "deny"}
            onClick={() => void decide("deny")}
          >
            {busy === "deny" ? "Denying…" : "Deny"}
          </Button>
        </form>
        {error ? <Notice tone="error">{error}</Notice> : null}
        <p className="text-[10px] uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
          Redirect: {redirectUri || "—"}
        </p>
        <p className="text-[10px] uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
          client_id {clientId}
        </p>
      </div>
    </AuthShell>
  );
}

export default function ConsentPage() {
  return (
    <Suspense fallback={<ScreenFallback title="Loading" />}>
      <ConsentForm />
    </Suspense>
  );
}
