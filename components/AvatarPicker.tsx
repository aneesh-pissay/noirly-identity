"use client";

import { useRef, useState } from "react";
import { Notice } from "@/components/auth-ui";
import { getCsrf } from "@/lib/auth/csrf-client";
import { AVATAR_SIZE } from "@/lib/account/avatar-image";

type Props = { avatarUrl: string | null; name: string; onChange: (avatarUrl: string | null) => void };

const button = "rounded-xl border border-[var(--hairline)] px-3 py-2 text-sm focus-visible:outline-2 disabled:opacity-50";

/** Crops a picked photo to its centre square and shrinks it, so what's uploaded is small and already the right shape. */
async function squareImage(file: File): Promise<Blob> {
  const bitmap = await createImageBitmap(file);
  const side = Math.min(bitmap.width, bitmap.height);
  const canvas = document.createElement("canvas");
  canvas.width = AVATAR_SIZE;
  canvas.height = AVATAR_SIZE;
  const context = canvas.getContext("2d");
  if (!context) throw new Error("This browser can't prepare the photo");
  context.drawImage(bitmap, (bitmap.width - side) / 2, (bitmap.height - side) / 2, side, side, 0, 0, AVATAR_SIZE, AVATAR_SIZE);
  bitmap.close();
  // WebP where the browser can make it; it falls back to PNG on its own otherwise.
  const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, "image/webp", 0.9));
  if (!blob) throw new Error("This browser can't prepare the photo");
  return blob;
}

/** The account's profile photo: upload one (from this device) or remove it. */
export function AvatarPicker({ avatarUrl, name, onChange }: Props) {
  const input = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function send(init: RequestInit) {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/auth/avatar", { credentials: "include", ...init, headers: { ...init.headers, "x-csrf-token": await getCsrf() } });
      const data = (await res.json()) as { avatarUrl?: string | null; message?: string };
      if (!res.ok) throw new Error(data.message ?? "Could not update your photo");
      onChange(data.avatarUrl ?? null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not update your photo");
    } finally {
      setBusy(false);
      if (input.current) input.current.value = "";
    }
  }

  async function pick(file: File) {
    try {
      const blob = await squareImage(file);
      await send({ method: "POST", headers: { "content-type": blob.type }, body: blob });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not read that photo");
    }
  }

  const initials = name.split(/\s+/).filter(Boolean).slice(0, 2).map((part) => part[0]!.toUpperCase()).join("") || "?";

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-4">
        {avatarUrl ? (
          // eslint-disable-next-line @next/next/no-img-element -- served by Identity or Google, already sized
          <img src={avatarUrl} alt="Your profile photo" width={72} height={72} className="h-18 w-18 rounded-full object-cover" referrerPolicy="no-referrer" />
        ) : (
          <span aria-hidden className="flex h-18 w-18 items-center justify-center rounded-full bg-[var(--surface-2)] text-lg font-semibold">{initials}</span>
        )}
        <div className="flex flex-wrap gap-2">
          <label className={`${button} cursor-pointer`}>
            {avatarUrl ? "Change photo" : "Add photo"}
            <input ref={input} type="file" accept="image/png,image/jpeg,image/webp" className="sr-only" disabled={busy} onChange={(event) => { const file = event.target.files?.[0]; if (file) void pick(file); }} />
          </label>
          {avatarUrl ? <button type="button" className={button} disabled={busy} onClick={() => void send({ method: "DELETE" })}>Remove photo</button> : null}
        </div>
      </div>
      <p className="text-xs text-[var(--muted-foreground)]">Shown in every Noirly app. PNG, JPEG or WebP; it&apos;s cropped to a square.</p>
      {error ? <Notice tone="error">{error}</Notice> : null}
    </div>
  );
}
