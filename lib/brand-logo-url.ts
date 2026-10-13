/** Only the exact configured deployment logo may be fetched. */
export function resolveBrandLogoUrl(src: string, baseUrl: string): string | null {
  try { return new URL(src, baseUrl).href; } catch { return null; }
}

export function isAllowedBrandLogoUrl(absoluteUrl: string, requestOrigin: string): boolean {
  try {
    const configured = process.env.NEXT_PUBLIC_IDENTITY_LOGO_URL ?? "/brand-mark.svg";
    const expected = new URL(configured, requestOrigin);
    const url = new URL(absoluteUrl);
    if (url.href !== expected.href || url.username || url.password || url.hash) return false;
    if (configured.startsWith("/") && !configured.startsWith("//")) {
      return url.origin === new URL(requestOrigin).origin && url.pathname === "/brand-mark.svg" && !url.search;
    }
    return url.protocol === "https:" && !url.port &&
      url.hostname !== "localhost" && !url.hostname.endsWith(".localhost") &&
      !url.hostname.endsWith(".local") && !/^[\d.]+$/.test(url.hostname) && !url.hostname.includes(":");
  } catch { return false; }
}
