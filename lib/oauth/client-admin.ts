import { AppError } from "@/lib/api/errors";
import { generateSecureToken } from "@/lib/security/crypto";
import { hashPassword } from "@/lib/security/password";
import {
  parseAndroidSha1List,
  Sha1ParseError,
} from "@/lib/oauth/android-sha1";
import {
  OriginParseError,
  uniqueStrings,
  urisFromOrigins,
} from "@/lib/oauth/app-origins";
import { OAuthClient, type OAuthClientDocument } from "@/models/OAuthClient";
import { AccessToken } from "@/models/AccessToken";
import type { ClientType, PublicOAuthClient } from "@/types";
import { environmentClientId, inferEnvironment, redirectProblem, type AppEnvironment } from "@/lib/oauth/environments";

const DEFAULT_SCOPES = [
  "openid",
  "profile",
  "email",
  "offline_access",
  "roles",
] as const;

export function toPublicOAuthClient(client: OAuthClientDocument): PublicOAuthClient {
  return {
    clientId: client.clientId,
    appKey: client.appKey ?? client.clientId,
    environment: environmentOf(client),
    environmentSet: Boolean(client.environment),
    ownerIds: (client.ownerIds ?? []).map(String),
    accessMode: client.accessPolicy?.mode ?? "anyone",
    name: client.name,
    description: client.description,
    status: client.status,
    clientType: client.clientType,
    redirectUris: client.redirectUris,
    postLogoutRedirectUris: client.postLogoutRedirectUris,
    allowedScopes: client.allowedScopes,
    requirePkce: client.requirePkce,
    requireConsent: client.requireConsent,
    requireMfa: Boolean(client.requireMfa),
    backchannelLogoutUri: client.backchannelLogoutUri ?? null,
    frontchannelLogoutUri: client.frontchannelLogoutUri ?? null,
    dataExportUri: client.dataExportUri ?? null,
    lifecycleWebhookUri: client.lifecycleWebhookUri ?? null,
    lifecycleEvents: client.lifecycleEvents ?? [],
    // Only while it still works.
    previousSecretExpiresAt: client.previousSecretExpiresAt && client.previousSecretExpiresAt > new Date() ? client.previousSecretExpiresAt.toISOString() : null,
    previousSecretLastUsedAt: client.previousSecretExpiresAt && client.previousSecretExpiresAt > new Date() && client.previousSecretLastUsedAt ? client.previousSecretLastUsedAt.toISOString() : null,
    androidSha1Fingerprints: client.androidSha1Fingerprints ?? [],
    createdAt: client.createdAt.toISOString(),
    updatedAt: client.updatedAt.toISOString(),
  };
}

export async function listOAuthClients(filter: Record<string, unknown> = {}): Promise<PublicOAuthClient[]> {
  const clients = await OAuthClient.find(filter)
    .sort({ name: 1, clientId: 1 })
    .exec();
  return clients.map(toPublicOAuthClient);
}

function parseSha1Input(values?: string[]): string[] {
  if (!values?.length) return [];
  try {
    return parseAndroidSha1List(values);
  } catch (error) {
    if (error instanceof Sha1ParseError) {
      throw new AppError(error.message, 400, "validation_error");
    }
    throw error;
  }
}

function parseRedirectUris(values: string[]): string[] {
  const next: string[] = [];
  for (const raw of values) {
    const trimmed = raw.trim();
    if (!trimmed) continue;
    let parsed: URL;
    try {
      parsed = new URL(trimmed);
    } catch {
      throw new AppError(`Invalid redirect URI: ${trimmed}`, 400, "validation_error");
    }
    if (!parsed.protocol || parsed.protocol === "javascript:") {
      throw new AppError(`Invalid redirect URI: ${trimmed}`, 400, "validation_error");
    }
    next.push(trimmed);
  }
  if (next.length === 0) {
    throw new AppError("At least one redirect URI is required", 400, "validation_error");
  }
  return uniqueStrings(next);
}

function resolveUris(input: {
  origins?: string[];
  redirectUris?: string[];
  callbackPath?: string;
}): { redirectUris: string[]; postLogoutRedirectUris: string[] } {
  if (input.redirectUris?.length) {
    const redirectUris = parseRedirectUris(input.redirectUris);
    return {
      redirectUris,
      postLogoutRedirectUris: redirectUris
        .filter((uri) => uri.startsWith("http://") || uri.startsWith("https://"))
        .map((uri) => {
          try {
            return new URL("/", uri).origin + "/";
          } catch {
            return uri;
          }
        }),
    };
  }
  if (input.origins?.length) {
    try {
      const uris = urisFromOrigins(input.origins, input.callbackPath);
      return {
        redirectUris: uris.redirectUris,
        postLogoutRedirectUris: uris.postLogoutRedirectUris,
      };
    } catch (error) {
      if (error instanceof OriginParseError) {
        throw new AppError(error.message, 400, "validation_error");
      }
      throw error;
    }
  }
  throw new AppError(
    "Provide at least one app origin or redirect URI",
    400,
    "validation_error",
  );
}

export async function registerAppClient(input: {
  clientId: string;
  name: string;
  clientType?: ClientType;
  origins?: string[];
  redirectUris?: string[];
  callbackPath?: string;
  requireConsent?: boolean;
  androidSha1Fingerprints?: string[];
  environment?: AppEnvironment;
}): Promise<{
  client: PublicOAuthClient;
  clientSecret: string | null;
  created: boolean;
}> {
  const clientType = input.clientType ?? "confidential";
  const uris = resolveUris(input);
  const sha1s = parseSha1Input(input.androidSha1Fingerprints);
  const existing = await OAuthClient.findOne({ clientId: input.clientId });

  if (existing) {
    existing.name = input.name;
    existing.redirectUris = uniqueStrings([
      ...existing.redirectUris,
      ...uris.redirectUris,
    ]);
    if (existing.environment) assertRedirectsFit(existing.environment, existing.redirectUris);
    existing.postLogoutRedirectUris = uniqueStrings([
      ...existing.postLogoutRedirectUris,
      ...uris.postLogoutRedirectUris,
    ]);
    existing.androidSha1Fingerprints = uniqueStrings([
      ...(existing.androidSha1Fingerprints ?? []),
      ...sha1s,
    ]);
    existing.status = "active";
    if (input.requireConsent !== undefined) {
      existing.requireConsent = input.requireConsent;
    }
    await existing.save();
    return {
      client: toPublicOAuthClient(existing),
      clientSecret: null,
      created: false,
    };
  }

  // Rules apply once an environment is chosen; without one, the client stays as
  // clients always were (its environment is only worked out for labels).
  if (input.environment) assertRedirectsFit(input.environment, uris.redirectUris);
  const clientSecret =
    clientType === "confidential" ? generateSecureToken(32) : null;
  const created = await OAuthClient.create({
    clientId: input.clientId,
    appKey: input.clientId,
    environment: input.environment ?? null,
    clientSecretHash: clientSecret ? await hashPassword(clientSecret) : null,
    name: input.name,
    description:
      clientType === "public"
        ? `Public native OAuth client for ${input.name}`
        : `Confidential OAuth client for ${input.name}`,
    redirectUris: uris.redirectUris,
    postLogoutRedirectUris: uris.postLogoutRedirectUris,
    allowedScopes: [...DEFAULT_SCOPES],
    clientType,
    status: "active",
    requirePkce: true,
    requireConsent: input.requireConsent ?? false,
    androidSha1Fingerprints: sha1s,
  });

  return {
    client: toPublicOAuthClient(created),
    clientSecret,
    created: true,
  };
}

/**
 * A logout URI an app registers: absolute https, or http on localhost outside
 * production, with no fragment. Empty clears it.
 */
export function logoutUri(value: string | null, label: string): string | null {
  if (!value?.trim()) return null;
  let url: URL;
  try {
    url = new URL(value.trim());
  } catch {
    throw new AppError(`${label} must be an absolute URL`, 400, "validation_error");
  }
  const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  const httpAllowed = local && process.env.NODE_ENV !== "production";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && httpAllowed)) {
    throw new AppError(`${label} must use https`, 400, "validation_error");
  }
  if (url.hash) throw new AppError(`${label} can't have a fragment`, 400, "validation_error");
  return url.toString();
}

/** The client's environment; older clients' is worked out from where they redirect. */
export function environmentOf(client: { environment?: AppEnvironment | null; redirectUris: string[] }): AppEnvironment {
  return client.environment ?? inferEnvironment(client.redirectUris);
}

function assertRedirectsFit(environment: AppEnvironment, redirectUris: string[]) {
  const problem = redirectProblem(environment, redirectUris);
  if (problem) throw new AppError(problem, 400, "validation_error");
}

/**
 * Adds an environment to an app: a new client with its own client_id
 * (environmentClientId), secret and redirect URIs, and the app's settings
 * (type, scopes, PKCE, consent, second step). Logout URIs, Android
 * fingerprints and API grants aren't copied: each environment has its own.
 */
export async function addAppEnvironment(sourceClientId: string, input: {
  environment: AppEnvironment;
  origins?: string[];
  redirectUris?: string[];
  callbackPath?: string;
}): Promise<{ client: PublicOAuthClient; clientSecret: string | null }> {
  const source = await OAuthClient.findOne({ clientId: sourceClientId }).lean();
  if (!source) throw new AppError("Unknown OAuth client", 404, "not_found");
  const appKey = source.appKey ?? source.clientId;
  const siblings = await OAuthClient.find({ $or: [{ appKey }, { clientId: appKey }] }).select("clientId environment redirectUris").lean();
  if (siblings.some((c) => environmentOf(c) === input.environment)) {
    throw new AppError(`This app already has a ${input.environment} environment`, 409, "conflict");
  }
  const clientId = environmentClientId(appKey, input.environment);
  if (await OAuthClient.exists({ clientId })) throw new AppError(`The client ID ${clientId} is already taken`, 409, "conflict");
  const uris = resolveUris(input);
  assertRedirectsFit(input.environment, uris.redirectUris);
  const clientSecret = source.clientType === "confidential" ? generateSecureToken(32) : null;
  const created = await OAuthClient.create({
    clientId,
    appKey,
    environment: input.environment,
    clientSecretHash: clientSecret ? await hashPassword(clientSecret) : null,
    name: source.name,
    description: `${source.description} (${input.environment})`,
    redirectUris: uris.redirectUris,
    postLogoutRedirectUris: uris.postLogoutRedirectUris,
    allowedScopes: source.allowedScopes,
    clientType: source.clientType,
    status: "active",
    requirePkce: source.requirePkce,
    requireConsent: source.requireConsent,
    requireMfa: Boolean(source.requireMfa),
    ownerIds: source.ownerIds ?? [],
  });
  // The app it came from joins the group; its environment is settled too when its redirects fit one.
  if (!source.appKey || !source.environment) {
    const settled = source.environment ?? (redirectProblem(environmentOf(source), source.redirectUris) ? null : environmentOf(source));
    await OAuthClient.updateOne({ _id: source._id }, { $set: { appKey, environment: settled } });
  }
  return { client: toPublicOAuthClient(created), clientSecret };
}

export const DEFAULT_SECRET_OVERLAP_SECONDS = 86_400;
export const MAX_SECRET_OVERLAP_SECONDS = 7 * 86_400;

function clearPreviousSecret(client: { previousSecretHash?: string | null; previousSecretExpiresAt?: Date | null; previousSecretLastUsedAt?: Date | null }) {
  client.previousSecretHash = null;
  client.previousSecretExpiresAt = null;
  client.previousSecretLastUsedAt = null;
}

export async function updateAppClient(
  clientId: string,
  input: {
    name?: string;
    clientType?: ClientType;
    origins?: string[];
    redirectUris?: string[];
    callbackPath?: string;
    rotateSecret?: boolean;
    /** With rotateSecret: how long the old secret keeps working (0 for at once). Default a day. */
    secretOverlapSeconds?: number;
    /** Stop accepting the previous secret now. */
    dropPreviousSecret?: boolean;
    /** Revoke the app's own (client credentials) tokens: for a leaked secret. */
    revokeMachineTokens?: boolean;
    environment?: AppEnvironment;
    status?: "active" | "disabled";
    requireConsent?: boolean;
    requireMfa?: boolean;
    backchannelLogoutUri?: string | null;
    frontchannelLogoutUri?: string | null;
    dataExportUri?: string | null;
    lifecycleWebhookUri?: string | null;
    lifecycleEvents?: string[];
    androidSha1Fingerprints?: string[];
    replaceUris?: boolean;
  },
): Promise<{ client: PublicOAuthClient; clientSecret: string | null }> {
  const existing = await OAuthClient.findOne({ clientId }).select("+clientSecretHash +previousSecretHash");
  if (!existing) {
    throw new AppError("Unknown OAuth client", 404, "not_found");
  }

  if (input.name) {
    existing.name = input.name;
  }

  const hasUriUpdate = Boolean(input.origins?.length || input.redirectUris?.length);
  if (hasUriUpdate) {
    const uris = resolveUris({
      origins: input.origins,
      redirectUris: input.redirectUris,
      callbackPath: input.callbackPath,
    });
    if (input.replaceUris || input.redirectUris?.length) {
      existing.redirectUris = uris.redirectUris;
      existing.postLogoutRedirectUris = uris.postLogoutRedirectUris;
    } else {
      existing.redirectUris = uniqueStrings([
        ...existing.redirectUris,
        ...uris.redirectUris,
      ]);
      existing.postLogoutRedirectUris = uniqueStrings([
        ...existing.postLogoutRedirectUris,
        ...uris.postLogoutRedirectUris,
      ]);
    }
  }

  // Redirects stay within what the environment is for, once it's been chosen.
  const environment = input.environment ?? existing.environment ?? null;
  if (environment && (hasUriUpdate || input.environment)) {
    assertRedirectsFit(environment, existing.redirectUris);
    existing.environment = environment;
    existing.appKey = existing.appKey ?? existing.clientId;
  }

  if (input.androidSha1Fingerprints !== undefined) {
    existing.androidSha1Fingerprints = parseSha1Input(input.androidSha1Fingerprints);
  }
  if (input.status) {
    existing.status = input.status;
  }
  if (input.requireConsent !== undefined) {
    existing.requireConsent = input.requireConsent;
  }
  if (input.requireMfa !== undefined) {
    existing.requireMfa = input.requireMfa;
  }
  if (input.backchannelLogoutUri !== undefined) {
    existing.backchannelLogoutUri = logoutUri(input.backchannelLogoutUri, "Back-channel logout URI");
  }
  if (input.frontchannelLogoutUri !== undefined) {
    existing.frontchannelLogoutUri = logoutUri(input.frontchannelLogoutUri, "Front-channel logout URI");
  }
  if (input.dataExportUri !== undefined) {
    existing.dataExportUri = logoutUri(input.dataExportUri, "Data export URI");
  }
  if (input.lifecycleWebhookUri !== undefined) {
    existing.lifecycleWebhookUri = logoutUri(input.lifecycleWebhookUri, "Lifecycle webhook URI");
  }
  if (input.lifecycleEvents !== undefined) {
    const { LIFECYCLE_EVENTS } = await import("@/lib/webhooks/lifecycle");
    const unknown = input.lifecycleEvents.filter((e) => !(LIFECYCLE_EVENTS as readonly string[]).includes(e));
    if (unknown.length) throw new AppError(`Unknown lifecycle events: ${unknown.join(", ")}`, 400, "invalid_request");
    existing.lifecycleEvents = [...new Set(input.lifecycleEvents)];
  }

  let clientSecret: string | null = null;
  const nextType = input.clientType ?? existing.clientType;
  if (input.clientType && input.clientType !== existing.clientType) {
    existing.clientType = input.clientType;
    existing.description =
      input.clientType === "public"
        ? `Public native OAuth client for ${existing.name}`
        : `Confidential OAuth client for ${existing.name}`;
    if (input.clientType === "public") {
      existing.clientSecretHash = null;
      clearPreviousSecret(existing);
    } else if (!input.rotateSecret) {
      // Confidential needs a secret; mint one when promoting from public.
      clientSecret = generateSecureToken(32);
      existing.clientSecretHash = await hashPassword(clientSecret);
    }
  }

  if (input.rotateSecret) {
    if (nextType === "public") {
      throw new AppError(
        "Public clients do not have a client secret to rotate",
        400,
        "invalid_client",
      );
    }
    const overlap = input.secretOverlapSeconds ?? DEFAULT_SECRET_OVERLAP_SECONDS;
    if (!Number.isInteger(overlap) || overlap < 0 || overlap > MAX_SECRET_OVERLAP_SECONDS) {
      throw new AppError("The overlap must be between 0 seconds and 7 days", 400, "validation_error");
    }
    // The old secret keeps working for a while, so the app can switch over.
    if (overlap > 0 && existing.clientSecretHash) {
      existing.previousSecretHash = existing.clientSecretHash;
      existing.previousSecretExpiresAt = new Date(Date.now() + overlap * 1000);
      existing.previousSecretLastUsedAt = null;
    } else {
      clearPreviousSecret(existing);
    }
    clientSecret = generateSecureToken(32);
    existing.clientSecretHash = await hashPassword(clientSecret);
  }

  if (input.dropPreviousSecret) clearPreviousSecret(existing);

  await existing.save();
  if (input.revokeMachineTokens) {
    await AccessToken.updateMany({ clientId, kind: "machine", revokedAt: null }, { $set: { revokedAt: new Date() } });
  }
  return { client: toPublicOAuthClient(existing), clientSecret };
}

export async function deleteAppClient(clientId: string): Promise<void> {
  const deleted = await OAuthClient.findOneAndDelete({ clientId });
  if (!deleted) {
    throw new AppError("Unknown OAuth client", 404, "not_found");
  }
}
