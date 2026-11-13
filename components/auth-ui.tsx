"use client";

import Link from "next/link";
import { Loader2 } from "lucide-react";
import {
  AuthShell,
  Button,
  Input,
  Label,
  Textarea,
  cn,
} from "@noirly-dev/ui";
import { AuthLogo } from "@/components/AuthLogo";
import {
  type ComponentProps,
  type InputHTMLAttributes,
  type ReactNode,
  type TextareaHTMLAttributes,
} from "react";

export function FormField({
  label,
  id,
  className,
  ...props
}: InputHTMLAttributes<HTMLInputElement> & { label: string }) {
  const fieldId = id ?? props.name ?? label.toLowerCase().replace(/\s+/g, "-");

  return (
    <div className={cn("flex flex-col gap-2", className)}>
      <Label htmlFor={fieldId}>{label}</Label>
      <Input id={fieldId} {...props} />
    </div>
  );
}

export function FormTextarea({
  label,
  id,
  className,
  ...props
}: TextareaHTMLAttributes<HTMLTextAreaElement> & { label: string }) {
  const fieldId = id ?? props.name ?? label.toLowerCase().replace(/\s+/g, "-");

  return (
    <div className={cn("flex flex-col gap-2", className)}>
      <Label htmlFor={fieldId}>{label}</Label>
      <Textarea id={fieldId} {...props} />
    </div>
  );
}

export function BusyOverlay({ label = "Working" }: { label?: string }) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-[var(--background)]/85 backdrop-blur-sm"
      role="status"
      aria-live="polite"
      aria-busy="true"
    >
      <div className="flex flex-col items-center gap-3 px-6">
        <Loader2 className="h-8 w-8 animate-spin text-[var(--accent)]" />
        <p className="text-xs font-medium uppercase tracking-[0.12em] text-[var(--muted-foreground)]">
          {label}
        </p>
      </div>
    </div>
  );
}

export function Notice({
  children,
  tone = "default",
}: {
  children: ReactNode;
  tone?: "default" | "success" | "error";
}) {
  return (
    <p
      role="alert"
      className={cn(
        "rounded-xl border px-3 py-2 text-sm",
        tone === "error"
          ? "border-red-500/20 bg-red-500/10 text-red-400"
          : tone === "success"
            ? "border-[var(--accent)]/20 bg-[var(--accent-soft)] text-[var(--foreground)]"
            : "border-[var(--hairline)] bg-[var(--surface-2)] text-[var(--foreground)]",
      )}
    >
      {children}
    </p>
  );
}

export function ScreenFallback({ title }: { title: string }) {
  return (
    <AuthShell logo={<AuthLogo />} title={title} lead="Please wait…">
      <div className="flex justify-center py-8">
        <Loader2 className="h-8 w-8 animate-spin text-[var(--accent)]" />
      </div>
    </AuthShell>
  );
}

export function TextLink({
  href,
  children,
  className,
}: {
  href: string;
  children: ReactNode;
  className?: string;
}) {
  const linkClass = cn(
    "text-sm text-[var(--muted-foreground)] underline underline-offset-4 transition-colors hover:text-[var(--foreground)]",
    className,
  );

  if (href.startsWith("/api/") || href.startsWith("http://") || href.startsWith("https://")) {
    return (
      <a href={href} className={linkClass}>
        {children}
      </a>
    );
  }

  return (
    <Link href={href} className={linkClass}>
      {children}
    </Link>
  );
}

export function SubmitButton({
  busy,
  busyLabel,
  children,
  className,
  ...props
}: ComponentProps<typeof Button> & {
  busy?: boolean;
  busyLabel?: string;
}) {
  return (
    <Button
      type="submit"
      className={cn("w-full", className)}
      disabled={busy || props.disabled}
      aria-busy={busy}
      {...props}
    >
      {busy ? (
        <>
          <Loader2 className="h-4 w-4 animate-spin" />
          {busyLabel ?? "Working…"}
        </>
      ) : (
        children
      )}
    </Button>
  );
}
