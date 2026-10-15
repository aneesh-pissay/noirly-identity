import { sameOriginPath, stripAuthorizePrompt } from "@/lib/auth/return-to";
import { getEnv } from "@/lib/config/env";
import { OAuthClient } from "@/models/OAuthClient";

export async function resolveOneTapReturnTo(
  candidate: string | null | undefined,
): Promise<string> {
  const env = getEnv();
  const app = env.APP_URL.replace(/\/$/, "");
  const fallback = `${app}/account`;
  if (!candidate) return fallback;

  if (/[\u0000-\u001f\u007f\\]/.test(candidate)) return fallback;
  if (candidate.startsWith("/")) {
    const path = sameOriginPath(candidate, app);
    return path ? `${app}${stripAuthorizePrompt(path)}` : fallback;
  }

  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return fallback;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return fallback;
  }

  const appOrigin = new URL(app).origin;
  if (url.origin === appOrigin) {
    return stripAuthorizePrompt(url.toString());
  }

  const clients = await OAuthClient.find({ status: "active" })
    .select("redirectUris")
    .lean();
  const allowed = new Set<string>();
  for (const client of clients) {
    for (const redirect of client.redirectUris) {
      try {
        allowed.add(new URL(redirect).origin);
      } catch {
        /* skip malformed */
      }
    }
  }
  if (!allowed.has(url.origin)) {
    return fallback;
  }
  if (!url.pathname.startsWith("/") || url.pathname.startsWith("//")) {
    return fallback;
  }
  return stripAuthorizePrompt(url.toString());
}
