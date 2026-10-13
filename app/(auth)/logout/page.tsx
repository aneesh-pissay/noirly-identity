"use client";
import { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import { securityRequest } from "@/components/security/client";

function Confirmation() {
  const params = useSearchParams();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function logout() {
    setBusy(true);
    try {
      const result = await securityRequest<{ redirectTo: string | null }>("/api/oidc/logout", Object.fromEntries(params));
      window.location.assign(result.redirectTo ?? "/login?logged_out=1");
    } catch { setError("Unable to sign out. Please try again."); setBusy(false); }
  }
  return <main className="mx-auto max-w-md space-y-5 px-6 py-12"><h1 className="text-2xl font-semibold">Sign out of Noirly Identity?</h1><p>This ends your current Identity session.</p>{error && <p role="alert">{error}</p>}<button className="rounded-xl border px-4 py-3 disabled:opacity-50" disabled={busy} onClick={() => void logout()}>{busy ? "Signing out…" : "Sign out"}</button><a className="ml-4 underline" href="/account">Cancel</a></main>;
}
export default function LogoutPage() { return <Suspense><Confirmation /></Suspense>; }
