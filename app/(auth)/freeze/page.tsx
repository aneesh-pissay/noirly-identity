"use client";

import { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import { AuthShell, Button } from "@noirly-dev/ui";
import { AuthLogo } from "@/components/AuthLogo";
import { Notice, ScreenFallback, TextLink } from "@/components/auth-ui";
import { securityRequest } from "@/components/security/client";

/** From a security alert: freeze the account at once, no sign-in needed. */
function Freeze() {
  const token = useSearchParams().get("token") ?? "";
  const [state, setState] = useState<"ask" | "done" | "error">("ask");
  const [message, setMessage] = useState("");
  async function freeze() {
    try {
      await securityRequest("/api/auth/freeze", { action: "freeze-link", token });
      setState("done");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "That didn't work");
      setState("error");
    }
  }
  return (
    <AuthShell logo={<AuthLogo />} title="Freeze your account" lead="If someone else is in your account, freeze it: nobody can sign in, every device is signed out, and apps lose access." footer={<TextLink href="/unfreeze">Unfreeze an account</TextLink>}>
      {state === "done" ? <Notice tone="success">Frozen. When you&apos;re ready, ask to unfreeze it; that takes a day after you confirm by email.</Notice> : (
        <div className="flex flex-col gap-3">
          {state === "error" ? <Notice tone="error">{message}</Notice> : null}
          <Button type="button" onClick={() => void freeze()}>Freeze my account now</Button>
        </div>
      )}
    </AuthShell>
  );
}

export default function FreezePage() {
  return <Suspense fallback={<ScreenFallback title="Loading" />}><Freeze /></Suspense>;
}
