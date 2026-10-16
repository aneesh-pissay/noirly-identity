import { randomUUID } from "node:crypto";
import { SignJWT } from "jose";
import { getEnv } from "@/lib/config/env";
import { getSigningKeys } from "@/lib/oidc/keys";
import { parseDeletionWebhooks, type DeletionWebhook } from "@/lib/account/deletion-webhooks";

/**
 * Tells apps that a space changed (members, roles, name, or it was deleted),
 * so they re-read it and update the teams linked to it.
 *
 * Targets come from `SPACE_WEBHOOKS` (`clientId=url` pairs, like
 * ACCOUNT_DELETION_WEBHOOKS). Each notice is a Security Event Token signed with
 * Identity's OIDC key: `aud` = the app's client id, `sub` = the space id. It
 * carries no member data; the app fetches the current state itself. Best
 * effort: apps also re-sync on their own, so a missed notice only delays.
 */

export const SPACE_CHANGED_EVENT = "https://noirly.dev/events/space-changed";
const DELIVERY_TIMEOUT_MS = 8000;

function configuredWebhooks(): DeletionWebhook[] {
  const env = getEnv();
  return parseDeletionWebhooks(env.SPACE_WEBHOOKS, env.NODE_ENV === "production");
}

export async function signSpaceChangedEvent(spaceId: string, clientId: string): Promise<string> {
  const env = getEnv();
  const keys = await getSigningKeys();
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ events: { [SPACE_CHANGED_EVENT]: { spaceId } } })
    .setProtectedHeader({ alg: "RS256", kid: keys.kid, typ: "secevent+jwt" })
    .setIssuer(env.OIDC_ISSUER)
    .setSubject(spaceId)
    .setAudience(clientId)
    .setIssuedAt(now)
    .setExpirationTime(now + 15 * 60)
    .setJti(randomUUID())
    .sign(keys.privateKey);
}

/** Never throws: the change itself is already saved. */
export async function notifySpaceChanged(spaceIds: string | string[]): Promise<void> {
  let hooks: DeletionWebhook[] = [];
  try {
    hooks = configuredWebhooks();
  } catch {
    console.error("SPACE_WEBHOOKS is misconfigured");
    return;
  }
  const ids = [...new Set(Array.isArray(spaceIds) ? spaceIds : [spaceIds])];
  await Promise.all(
    hooks.flatMap((hook) =>
      ids.map(async (spaceId) => {
        try {
          const response = await fetch(hook.url, {
            method: "POST",
            redirect: "error",
            headers: { "content-type": "application/secevent+jwt", accept: "application/json" },
            body: await signSpaceChangedEvent(spaceId, hook.clientId),
            signal: AbortSignal.timeout(DELIVERY_TIMEOUT_MS),
            cache: "no-store",
          });
          if (!response.ok) console.error(`Space notice to ${hook.clientId} failed: HTTP ${response.status}`);
        } catch {
          console.error(`Space notice to ${hook.clientId} failed`);
        }
      }),
    ),
  );
}
