"use client";

import { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import { AuthShell, Button } from "@noirly-dev/ui";
import { AuthLogo } from "@/components/AuthLogo";
import { Notice, ScreenFallback, TextLink } from "@/components/auth-ui";
import { securityRequest } from "@/components/security/client";

/** From the "your account is closing" email: keep the account. */
function Undo() {
  const token = useSearchParams().get("token") ?? "";
  const [state, setState] = useState<"ask" | "done" | "error">("ask");
  const [message, setMessage] = useState("");
  async function undo() {
    try {
      await securityRequest("/api/auth/close-account/undo", { token });
      setState("done");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "That didn't work");
      setState("error");
    }
  }
  return (
    <AuthShell logo={<AuthLogo />} title="Keep your account" lead="Your account is closing. Keep it, and nothing is deleted.">
      {state === "done" ? (
        <div className="flex flex-col gap-3">
          <Notice tone="success">Your account is open again. Sign in to use it; if you didn&apos;t close it yourself, change your password.</Notice>
          <TextLink href="/login">Sign in</TextLink>
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          {state === "error" ? <Notice tone="error">{message}</Notice> : null}
          <Button type="button" onClick={() => void undo()}>Keep my account</Button>
        </div>
      )}
    </AuthShell>
  );
}

export default function UndoClosurePage() {
  return <Suspense fallback={<ScreenFallback title="Loading" />}><Undo /></Suspense>;
}
