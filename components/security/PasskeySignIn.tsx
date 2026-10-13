"use client";
import { useState } from "react";
import { startAuthentication } from "@simplewebauthn/browser";
import type { PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/browser";
import { goReturnTo } from "@/lib/auth/return-to";
import { securityRequest } from "./client";

export function PasskeySignIn({ returnTo, secondFactor = false }: { returnTo?: string | null; secondFactor?: boolean }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function signIn() {
    setBusy(true); setError("");
    try {
      const { options } = await securityRequest<{ options: PublicKeyCredentialRequestOptionsJSON }>("/api/auth/mfa", { action: secondFactor ? "passkey-options" : "passkey-login-options" });
      const response = await startAuthentication({ optionsJSON: options });
      await securityRequest("/api/auth/mfa", { action: "passkey-verify", response });
      goReturnTo(returnTo ?? "/account");
    } catch (error) { setError(error instanceof Error ? error.message : "Passkey sign-in failed"); }
    finally { setBusy(false); }
  }
  return <div className="my-3 space-y-2">
    <button type="button" disabled={busy} onClick={() => void signIn()} className="w-full rounded-xl border border-[var(--hairline)] px-4 py-3 text-sm focus-visible:outline-2 disabled:opacity-50">{busy ? "Waiting for your passkey…" : "Sign in with a passkey"}</button>
    {error && <p role="alert" className="text-sm text-red-500">{error}</p>}
  </div>;
}
