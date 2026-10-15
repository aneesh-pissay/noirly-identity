const OAUTH_RETURN_COOKIE = "noirly_oauth_return";

export function withReturnTo(path: string, returnTo: string | null | undefined): string {
  if (!returnTo) return path;
  const [pathname, search = ""] = path.split("?");
  const params = new URLSearchParams(search);
  params.set("return_to", returnTo);
  const qs = params.toString();
  return qs ? `${pathname}?${qs}` : pathname;
}

export function withPopup(path: string, popup: boolean): string {
  if (!popup) return path;
  const [pathname, search = ""] = path.split("?");
  const params = new URLSearchParams(search);
  params.set("popup", "1");
  const qs = params.toString();
  return qs ? `${pathname}?${qs}` : pathname;
}

export function isPopupLogin(candidate?: string | null): boolean {
  return candidate === "1" || candidate === "popup";
}

export function stripAuthorizePrompt(candidate: string): string {
  try {
    const absolute =
      candidate.startsWith("http://") || candidate.startsWith("https://");
    const url = absolute
      ? new URL(candidate)
      : new URL(candidate, "https://noirly.invalid");
    if (url.pathname === "/api/oauth/authorize") {
      url.searchParams.delete("prompt");
    }
    if (absolute) return url.toString();
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return candidate;
  }
}

/**
 * `candidate` as a path on `origin`, or null if it would leave that origin.
 *
 * Resolved with the URL parser browsers use, rather than by inspecting the
 * string: browsers drop tabs and newlines and read `\` as `/`, so text like
 * "/<tab>/evil.example" looks relative but navigates to evil.example.
 */
export function sameOriginPath(candidate: string, origin: string): string | null {
  let base: URL;
  try {
    base = new URL(origin);
  } catch {
    return null;
  }
  // Anything a browser would strip or reinterpret has no place in a return path.
  if (/[\u0000-\u001f\u007f\\]/.test(candidate)) return null;
  try {
    const url = new URL(candidate, base);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    if (url.origin !== base.origin) return null;
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return null;
  }
}

export function sanitizeReturnTo(
  candidate: string | null | undefined,
  origin?: string,
): string | null {
  if (!candidate) return null;
  const allowedOrigin =
    origin ?? (typeof window !== "undefined" ? window.location.origin : "");
  if (allowedOrigin) return sameOriginPath(candidate, allowedOrigin);
  // No origin to compare with (server code that didn't pass one): only a path
  // that stays put on any origin, checked against a placeholder.
  return candidate.startsWith("/") ? sameOriginPath(candidate, "https://noirly.invalid") : null;
}

export function readOauthReturnCookie(): string | null {
  if (typeof document === "undefined") return null;
  const match = document.cookie
    .split("; ")
    .find((row) => row.startsWith(`${OAUTH_RETURN_COOKIE}=`));
  if (!match) return null;
  try {
    return sanitizeReturnTo(
      decodeURIComponent(match.slice(OAUTH_RETURN_COOKIE.length + 1)),
    );
  } catch {
    return null;
  }
}

export function goReturnTo(returnTo: string | null | undefined): void {
  const dest =
    sanitizeReturnTo(returnTo) ?? readOauthReturnCookie() ?? "/";
  window.location.assign(stripAuthorizePrompt(dest));
}
