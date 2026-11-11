"use client";

import { Suspense, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { AuthShell, Button } from "@noirly-dev/ui";
import { AuthLogo } from "@/components/AuthLogo";
import { Notice, ScreenFallback, TextLink } from "@/components/auth-ui";
import { getCsrf } from "@/lib/auth/csrf-client";

type Preview = { space: string; role: "owner" | "admin" | "member"; email: string };

/** Opened from an invitation email: shows the space and joins it. */
function AcceptInvitation() {
  const router = useRouter();
  const params = useSearchParams();
  const token = params.get("token") ?? "";
  const [preview, setPreview] = useState<Preview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [needsSignIn, setNeedsSignIn] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    void fetch(`/api/invitations?token=${encodeURIComponent(token)}`, { cache: "no-store", signal: controller.signal })
      .then(async (res) => {
        const data = (await res.json()) as { invitation?: Preview; message?: string };
        if (!res.ok || !data.invitation) throw new Error(data.message ?? "This invitation can't be used.");
        setPreview(data.invitation);
      })
      .catch((err: Error) => { if (!controller.signal.aborted) setError(err.message); });
    return () => controller.abort();
  }, [token]);

  async function join() {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/invitations", {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json", "x-csrf-token": await getCsrf() },
        body: JSON.stringify({ token }),
      });
      const data = (await res.json()) as { spaceId?: string; message?: string };
      if (res.status === 401) {
        setNeedsSignIn(true);
        return;
      }
      if (!res.ok) throw new Error(data.message ?? "Couldn't join");
      router.push("/spaces");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const back = `/invitations/accept?token=${encodeURIComponent(token)}`;
  return (
    <AuthShell logo={<AuthLogo />} title="Join a space" lead={preview ? `You're invited to ${preview.space} as ${preview.role === "member" ? "a member" : `an ${preview.role}`}.` : "Checking your invitation…"}>
      <div className="flex flex-col gap-4">
        {preview ? <p className="text-sm">It&apos;s for {preview.email}. Join with the Noirly account that has that address.</p> : null}
        {error ? <Notice tone="error">{error}</Notice> : null}
        {needsSignIn ? (
          <div className="flex flex-col gap-2 text-sm">
            <p>Sign in first, then you&apos;ll come back here.</p>
            <TextLink href={`/login?return_to=${encodeURIComponent(back)}`}>Sign in</TextLink>
            <TextLink href={`/register?return_to=${encodeURIComponent(back)}`}>Create an account</TextLink>
          </div>
        ) : null}
        {preview ? <Button type="button" disabled={busy} onClick={() => void join()}>{busy ? "Joining…" : "Join"}</Button> : null}
      </div>
    </AuthShell>
  );
}

export default function AcceptInvitationPage() {
  return <Suspense fallback={<ScreenFallback title="Loading" />}><AcceptInvitation /></Suspense>;
}
