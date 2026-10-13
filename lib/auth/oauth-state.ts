import { hmacSha256, safeEqualHex } from "@/lib/security/crypto";

export type OAuthStatePayload = {
  state: string;
  codeVerifier: string;
  returnTo: string;
  nonce: string;
  exp: number;
};

export function signOAuthState(payload: OAuthStatePayload): string {
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const sig = hmacSha256(body);
  return `${body}.${sig}`;
}

export function readOAuthState(raw: string | undefined | null): OAuthStatePayload | null {
  if (!raw) {
    return null;
  }
  const dot = raw.lastIndexOf(".");
  if (dot < 1) {
    return null;
  }
  const body = raw.slice(0, dot);
  const sig = raw.slice(dot + 1);
  const expected = hmacSha256(body);
  if (!safeEqualHex(sig, expected)) {
    return null;
  }
  try {
    const parsed = JSON.parse(
      Buffer.from(body, "base64url").toString("utf8"),
    ) as OAuthStatePayload;
    if (!parsed.state || !parsed.codeVerifier || !parsed.returnTo || !parsed.nonce) {
      return null;
    }
    if (typeof parsed.exp !== "number" || parsed.exp <= Date.now()) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function safeReturnTo(candidate: string | null, appUrl: string): string {
  if (!candidate) {
    return "/";
  }
  if (candidate.startsWith("/") && !candidate.startsWith("//") && !candidate.includes("\\")) {
    return candidate;
  }
  try {
    const url = new URL(candidate);
    const app = new URL(appUrl);
    if (url.origin === app.origin) {
      return `${url.pathname}${url.search}${url.hash}`;
    }
  } catch {
    return "/";
  }
  return "/";
}
