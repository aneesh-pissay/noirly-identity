"use client";
import { useState, useSyncExternalStore } from "react";
import { getCsrf } from "@/lib/auth/csrf-client";
import { LOCALE_CHOICES, TEXT_SIZES, type Accessibility, type Preferences as Prefs } from "@/lib/account/preferences";

const field = "h-10 w-full rounded-xl border border-[var(--hairline)] bg-[var(--surface-2)] px-3 text-sm";
const button = "rounded-xl border border-[var(--hairline)] px-4 py-2 text-sm focus-visible:outline-2 disabled:opacity-50";
const TEXT_SIZE_LABEL: Record<Accessibility["textSize"], string> = { default: "Default", large: "Large", larger: "Larger" };

type Device = { zone: string; zones: string[] };
let device: Device | null = null;
const NO_DEVICE: Device = { zone: "", zones: [] };

/** The browser's own time zone and the zones it knows; read once, and only in the browser (the server's differ). */
function readDevice(): Device {
  if (!device) {
    let zones: string[] = [];
    try {
      zones = (Intl as { supportedValuesOf?: (key: string) => string[] }).supportedValuesOf?.("timeZone") ?? [];
    } catch {
      zones = [];
    }
    device = { zone: Intl.DateTimeFormat().resolvedOptions().timeZone, zones };
  }
  return device;
}
const noSubscription = () => () => {};

/** Language, time zone and accessibility: followed by every Noirly app that reads them, and by these pages. */
export function Preferences({ initial }: { initial: Prefs }) {
  const [locale, setLocale] = useState(initial.locale ?? "");
  const [zoneinfo, setZoneinfo] = useState(initial.zoneinfo ?? "");
  const [accessibility, setAccessibility] = useState(initial.accessibility);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const { zone: deviceZone, zones } = useSyncExternalStore(noSubscription, readDevice, () => NO_DEVICE);
  const locales = LOCALE_CHOICES.some((c) => c.tag === locale) || !locale ? LOCALE_CHOICES : [{ tag: locale, label: locale }, ...LOCALE_CHOICES];

  async function save() {
    setBusy(true);
    setMessage("");
    try {
      const res = await fetch("/api/auth/me", {
        method: "PATCH",
        credentials: "include",
        headers: { "content-type": "application/json", "x-csrf-token": await getCsrf() },
        body: JSON.stringify({ locale: locale || null, zoneinfo: zoneinfo || null, accessibility }),
      });
      const data = (await res.json()) as { message?: string };
      if (!res.ok) throw new Error(data.message ?? "Could not save preferences");
      // The page's own text size, motion and contrast come from the server; load it again to show them.
      window.location.reload();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not save preferences");
      setBusy(false);
    }
  }

  const set = (patch: Partial<Accessibility>) => setAccessibility((current) => ({ ...current, ...patch }));

  return <section aria-labelledby="prefs-title" className="mx-auto my-8 w-full max-w-3xl space-y-5 rounded-2xl border border-[var(--hairline)] p-6">
    <h2 id="prefs-title" className="text-xl font-semibold">Language, time and accessibility</h2>
    <p className="text-sm opacity-75">Noirly apps use these to show dates, numbers and times your way. Leave a setting on your device&apos;s to follow whichever device you&apos;re on.</p>
    <form className="space-y-4" onSubmit={(event) => { event.preventDefault(); void save(); }}>
      <label className="block space-y-1 text-sm">
        <span>Language and region</span>
        <select className={field} value={locale} onChange={(event) => setLocale(event.target.value)}>
          <option value="">Use my device&apos;s</option>
          {locales.map((c) => <option key={c.tag} value={c.tag} lang={c.tag}>{c.label}</option>)}
        </select>
      </label>
      <label className="block space-y-1 text-sm">
        <span>Time zone</span>
        <select className={field} value={zoneinfo} onChange={(event) => setZoneinfo(event.target.value)}>
          <option value="">{deviceZone ? `Use my device's (${deviceZone.replaceAll("_", " ")})` : "Use my device's"}</option>
          {(zones.includes(zoneinfo) || !zoneinfo ? zones : [zoneinfo, ...zones]).map((zone) => <option key={zone} value={zone}>{zone.replaceAll("_", " ")}</option>)}
        </select>
      </label>
      <fieldset className="space-y-3 text-sm">
        <legend className="mb-1 font-medium">Accessibility</legend>
        <label className="flex items-center gap-3">
          <input type="checkbox" checked={accessibility.motion === "reduce"} onChange={(event) => set({ motion: event.target.checked ? "reduce" : "system" })} />
          Reduce motion and animation
        </label>
        <label className="flex items-center gap-3">
          <input type="checkbox" checked={accessibility.contrast === "more"} onChange={(event) => set({ contrast: event.target.checked ? "more" : "system" })} />
          More contrast
        </label>
        <label className="block space-y-1">
          <span>Text size</span>
          <select className={field} value={accessibility.textSize} onChange={(event) => set({ textSize: event.target.value as Accessibility["textSize"] })}>
            {TEXT_SIZES.map((size) => <option key={size} value={size}>{TEXT_SIZE_LABEL[size]}</option>)}
          </select>
        </label>
      </fieldset>
      {message && <p role="status" className="text-sm">{message}</p>}
      <button type="submit" className={button} disabled={busy}>{busy ? "Saving…" : "Save preferences"}</button>
    </form>
  </section>;
}
