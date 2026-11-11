/**
 * Preferences every Noirly app can follow: the language and region to
 * format in (`locale`, a BCP 47 tag), the time zone to show times in
 * (`zoneinfo`, an IANA name), and accessibility settings. Language and time
 * zone go to apps as the standard OIDC claims; accessibility goes as
 * `noirly_accessibility`. Null means "use the device's".
 */

export const MOTION = ["system", "reduce"] as const;
export const CONTRAST = ["system", "more"] as const;
export const TEXT_SIZES = ["default", "large", "larger"] as const;

export type Accessibility = {
  motion: (typeof MOTION)[number];
  contrast: (typeof CONTRAST)[number];
  textSize: (typeof TEXT_SIZES)[number];
};

export const DEFAULT_ACCESSIBILITY: Accessibility = { motion: "system", contrast: "system", textSize: "default" };

export type Preferences = { locale: string | null; zoneinfo: string | null; accessibility: Accessibility };

/** Offered on the account page; any valid tag is accepted through the API. */
export const LOCALE_CHOICES: Array<{ tag: string; label: string }> = [
  { tag: "en-IN", label: "English (India)" },
  { tag: "en-US", label: "English (United States)" },
  { tag: "en-GB", label: "English (United Kingdom)" },
  { tag: "hi-IN", label: "हिन्दी (भारत)" },
  { tag: "bn-IN", label: "বাংলা (ভারত)" },
  { tag: "ta-IN", label: "தமிழ் (இந்தியா)" },
  { tag: "te-IN", label: "తెలుగు (భారతదేశం)" },
  { tag: "mr-IN", label: "मराठी (भारत)" },
  { tag: "de-DE", label: "Deutsch (Deutschland)" },
  { tag: "es-ES", label: "Español (España)" },
  { tag: "fr-FR", label: "Français (France)" },
  { tag: "ja-JP", label: "日本語 (日本)" },
];

/** A language tag in its canonical form ("en-in" → "en-IN"), or null if it isn't one. */
export function canonicalLocale(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 35) return null;
  try {
    const [tag] = Intl.getCanonicalLocales(trimmed);
    return tag ?? null;
  } catch {
    return null;
  }
}

let knownZones: Map<string, string> | null = null;

/** The zones this runtime lists, by lower-case name. */
function zoneList(): Map<string, string> {
  if (!knownZones) {
    let zones: string[] = [];
    try {
      zones = (Intl as { supportedValuesOf?: (key: string) => string[] }).supportedValuesOf?.("timeZone") ?? [];
    } catch {
      zones = [];
    }
    knownZones = new Map(zones.map((zone) => [zone.toLowerCase(), zone]));
  }
  return knownZones;
}

/**
 * An IANA time zone as spelled in the zone list ("asia/kolkata" →
 * "Asia/Kolkata"), or null if there's no such zone. Not the runtime's own
 * resolved name: ICU still resolves some zones to retired names
 * ("Asia/Calcutta"), and apps should get the name the person chose.
 */
export function canonicalTimeZone(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 64) return null;
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: trimmed });
  } catch {
    return null;
  }
  const listed = zoneList().get(trimmed.toLowerCase());
  if (listed) return listed;
  // Valid but not in the list (an alias such as "Asia/Kolkata" on some runtimes): fix the case of each word.
  return trimmed.toLowerCase() === "utc" ? "UTC" : trimmed.replace(/[^/_-]+/g, (word) => word[0]!.toUpperCase() + word.slice(1).toLowerCase());
}

/** Stored settings, with anything missing filled in from the defaults. */
export function accessibilityOf(stored: Partial<Accessibility> | null | undefined): Accessibility {
  return {
    motion: MOTION.includes(stored?.motion as Accessibility["motion"]) ? stored!.motion! : DEFAULT_ACCESSIBILITY.motion,
    contrast: CONTRAST.includes(stored?.contrast as Accessibility["contrast"]) ? stored!.contrast! : DEFAULT_ACCESSIBILITY.contrast,
    textSize: TEXT_SIZES.includes(stored?.textSize as Accessibility["textSize"]) ? stored!.textSize! : DEFAULT_ACCESSIBILITY.textSize,
  };
}

/** What apps get under the `profile` scope: only what's set, as standard claims where there are standard ones. */
export function preferenceClaims(prefs: { locale?: string | null; zoneinfo?: string | null; accessibility?: Partial<Accessibility> | null }) {
  const claims: Record<string, unknown> = {};
  if (prefs.locale) claims.locale = prefs.locale;
  if (prefs.zoneinfo) claims.zoneinfo = prefs.zoneinfo;
  claims.noirly_accessibility = accessibilityOf(prefs.accessibility);
  return claims;
}
