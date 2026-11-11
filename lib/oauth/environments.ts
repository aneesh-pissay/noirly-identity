/**
 * Development, staging and production for one app. Each environment is its
 * own client (its own client_id, secret, redirect URIs, origins and logout
 * URIs), grouped by `appKey`, so nothing one environment holds works in
 * another: tokens, consent and API grants all follow the client_id. What
 * each environment may redirect to is held to what it's for. No server code:
 * the admin screen uses it too.
 */

export const APP_ENVIRONMENTS = ["production", "staging", "development"] as const;
export type AppEnvironment = (typeof APP_ENVIRONMENTS)[number];

export const ENVIRONMENT_LABEL: Record<AppEnvironment, string> = {
  production: "Production",
  staging: "Staging",
  development: "Development",
};

/** The client_id a new environment of an app gets: noirly-crm, noirly-crm-staging, noirly-crm-dev. */
export function environmentClientId(appKey: string, environment: AppEnvironment) {
  return environment === "production" ? appKey : `${appKey}-${environment === "staging" ? "staging" : "dev"}`;
}

/** Hosts that only exist on a developer's machine or test network. */
export function isLocalHost(hostname: string) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return host === "localhost" || host === "127.0.0.1" || host === "::1" || /\.(localhost|test|local)$/.test(host);
}

function webUris(uris: string[]) {
  return uris.flatMap((uri) => {
    try {
      const url = new URL(uri);
      return url.protocol === "http:" || url.protocol === "https:" ? [url] : [];
    } catch {
      return [];
    }
  });
}

/** For clients from before environments: local-only web redirects mean development. */
export function inferEnvironment(redirectUris: string[]): AppEnvironment {
  const web = webUris(redirectUris);
  return web.length > 0 && web.every((u) => isLocalHost(u.hostname)) ? "development" : "production";
}

/**
 * What each environment may redirect to. Production and staging: HTTPS on
 * real hosts only, so a token can't be sent to a developer's machine.
 * Development: local hosts only, so a dev client can't reach a live site.
 * Native app schemes (noirlyflow://oauth) are fine anywhere. Returns the
 * first problem, or null.
 */
export function redirectProblem(environment: AppEnvironment, redirectUris: string[]): string | null {
  for (const url of webUris(redirectUris)) {
    const local = isLocalHost(url.hostname);
    if (environment === "development") {
      if (!local) return `${url.origin} isn't a local address; development redirects stay on localhost`;
    } else {
      if (local) return `${url.origin} is a local address; use a development environment for it`;
      if (url.protocol !== "https:") return `${url.origin} must use https in ${environment}`;
    }
  }
  return null;
}

/** How an app is named to people: "Noirly CRM", or "Noirly CRM (Staging)" outside production. */
export function appDisplayName(name: string, environment: AppEnvironment | null | undefined) {
  return !environment || environment === "production" ? name : `${name} (${ENVIRONMENT_LABEL[environment]})`;
}
