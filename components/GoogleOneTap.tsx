"use client";

import { useEffect, useRef } from "react";
import { rememberEmail } from "@/lib/auth/recent-emails";

type CredentialResponse = { credential?: string };

type GoogleAccountsId = {
  initialize: (config: {
    client_id: string;
    callback: (response: CredentialResponse) => void;
    auto_select?: boolean;
    cancel_on_tap_outside?: boolean;
    nonce?: string;
    context?: string;
    itp_support?: boolean;
    use_fedcm_for_prompt?: boolean;
  }) => void;
  prompt: () => void;
  renderButton: (parent: HTMLElement, options: Record<string, unknown>) => void;
  disableAutoSelect: () => void;
};

declare global {
  interface Window {
    google?: { accounts: { id: GoogleAccountsId } };
  }
}

const GSI_SRC = "https://accounts.google.com/gsi/client";

function loadGsi(): Promise<GoogleAccountsId> {
  return new Promise((resolve, reject) => {
    if (window.google?.accounts.id) {
      resolve(window.google.accounts.id);
      return;
    }
    const existing = document.querySelector<HTMLScriptElement>(`script[src="${GSI_SRC}"]`);
    if (existing) {
      existing.addEventListener("load", () => {
        if (window.google?.accounts.id) resolve(window.google.accounts.id);
        else reject(new Error("Google Identity Services failed to load"));
      });
      existing.addEventListener("error", () => reject(new Error("Google Identity Services failed to load")));
      return;
    }
    const script = document.createElement("script");
    script.src = GSI_SRC;
    script.async = true;
    script.defer = true;
    script.onload = () => {
      if (window.google?.accounts.id) resolve(window.google.accounts.id);
      else reject(new Error("Google Identity Services failed to load"));
    };
    script.onerror = () => reject(new Error("Google Identity Services failed to load"));
    document.head.appendChild(script);
  });
}

function emailFromCredential(credential: string): string | null {
  try {
    const payload = credential.split(".")[1];
    if (!payload) return null;
    const json = JSON.parse(
      atob(payload.replace(/-/g, "+").replace(/_/g, "/")),
    ) as { email?: string };
    return typeof json.email === "string" ? json.email : null;
  } catch {
    return null;
  }
}

type Props = {
  clientId: string;
  returnTo?: string | null;
  identityOrigin?: string;
  context?: "signin" | "signup" | "use";
  popup?: boolean;
  autoPrompt?: boolean;
  onCredential?: (input: { credential: string; nonce: string }) => void;
};

export function GoogleOneTap({
  clientId,
  returnTo,
  identityOrigin,
  context = "signin",
  popup = false,
  autoPrompt = true,
  onCredential,
}: Props) {
  const buttonRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!clientId) return;
    let cancelled = false;

    void Promise.all([loadGsi(), fetch("/api/auth/google/nonce", { credentials: "same-origin" }).then(async (response) => {
      if (!response.ok) throw new Error("Google sign-in unavailable");
      return response.json() as Promise<{ nonce: string }>;
    })])
      .then(([accounts, { nonce }]) => {
        if (cancelled) return;
        const inPopup =
          popup ||
          window.name === "noirly-identity" ||
          Boolean(window.opener);
        accounts.initialize({
          client_id: clientId,
          auto_select: false,
          cancel_on_tap_outside: !inPopup,
          itp_support: true,
          use_fedcm_for_prompt: !inPopup,
          context,
          nonce,
          callback: (response) => {
            const credential = response.credential;
            if (!credential) return;
            const email = emailFromCredential(credential);
            if (email) rememberEmail(email);
            if (onCredential) {
              onCredential({ credential, nonce });
              return;
            }
            const form = document.createElement("form");
            form.method = "POST";
            form.action = `${identityOrigin ?? ""}/api/auth/google/one-tap`;
            form.style.display = "none";
            const fields: Record<string, string> = { credential, nonce };
            if (returnTo) fields.return_to = returnTo;
            for (const [name, value] of Object.entries(fields)) {
              const input = document.createElement("input");
              input.type = "hidden";
              input.name = name;
              input.value = value;
              form.appendChild(input);
            }
            document.body.appendChild(form);
            form.submit();
          },
        });
        accounts.disableAutoSelect();
        if (autoPrompt) {
          accounts.prompt();
        }
        if (buttonRef.current) {
          buttonRef.current.innerHTML = "";
          accounts.renderButton(buttonRef.current, {
            type: "standard",
            theme: "outline",
            size: "large",
            text: "signin_with",
            shape: "rectangular",
            logo_alignment: "left",
            width: buttonRef.current.offsetWidth || 336,
          });
        }
      })
      .catch(() => undefined);

    return () => {
      cancelled = true;
    };
  }, [autoPrompt, clientId, context, identityOrigin, onCredential, popup, returnTo]);

  return (
    <div className="flex flex-col gap-3">
      <div ref={buttonRef} className="flex min-h-10 w-full justify-center" />
      <p className="text-[10px] uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
        Choose any Google account — One Tap or the button above
      </p>
    </div>
  );
}
