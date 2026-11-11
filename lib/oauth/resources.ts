import { AppError, OAuthError } from "@/lib/api/errors";
import { SUPPORTED_SCOPES } from "@/types";
import { ApiResource, type ApiResourceDocument } from "@/models/ApiResource";

/**
 * RFC 8707 resource indicators: an app names the API it wants a token for
 * (`resource`), on the authorization request and again at the token
 * endpoint. Only registered, active APIs that list the app are accepted;
 * anything else is `invalid_target`.
 */

export const API_SCOPE_PATTERN = /^[a-z][a-z0-9_.:-]{1,63}$/;
export const RESOURCE_TTL_MIN = 60;
export const RESOURCE_TTL_MAX = 3600;

/** `resource` may be repeated; Identity carries the list space-separated (URIs hold no spaces). */
export function parseResourceParam(value: string | null | undefined): string[] {
  return [...new Set((value ?? "").split(/\s+/).filter(Boolean))];
}

export async function resolveResources(clientId: string, identifiers: string[]): Promise<ApiResourceDocument[]> {
  if (identifiers.length === 0) return [];
  if (identifiers.length > 5) throw new OAuthError("invalid_target", "Too many resources");
  const found = await ApiResource.find({ identifier: { $in: identifiers }, status: "active" }).lean<ApiResourceDocument[]>();
  for (const identifier of identifiers) {
    const resource = found.find((r) => r.identifier === identifier);
    if (!resource || !resource.allowedClientIds.includes(clientId)) {
      throw new OAuthError("invalid_target", `Unknown or unavailable resource: ${identifier}`);
    }
  }
  return identifiers.map((id) => found.find((r) => r.identifier === id)!);
}

/** Splits requested scopes into the APIs' own and the rest (OpenID Connect's). */
export function splitScopes(requested: string[], resources: Pick<ApiResourceDocument, "scopes">[]) {
  const apiNames = new Set(resources.flatMap((r) => r.scopes.map((s) => s.name)));
  return {
    api: requested.filter((s) => apiNames.has(s)),
    oidc: requested.filter((s) => !apiNames.has(s)),
  };
}

/** The scopes of `granted` that belong to this API: what its token carries. */
export function scopesFor(resource: Pick<ApiResourceDocument, "scopes">, granted: string[]) {
  const own = new Set(resource.scopes.map((s) => s.name));
  return granted.filter((s) => own.has(s));
}

/** Registers or updates an API (admin). */
export async function saveApiResource(input: {
  identifier: string;
  name: string;
  scopes?: Array<{ name: string; description?: string }>;
  accessTokenTtlSeconds?: number;
  allowedClientIds?: string[];
  /** Apps that may call it as themselves (client credentials), with their scopes. */
  machineGrants?: Array<{ clientId: string; scopes: string[] }>;
  status?: "active" | "disabled";
}) {
  let url: URL;
  try {
    url = new URL(input.identifier);
  } catch {
    throw new AppError("The identifier must be an absolute URI", 400, "validation_error");
  }
  if (url.hash) throw new AppError("The identifier can't have a fragment", 400, "validation_error");
  for (const scope of input.scopes ?? []) {
    if (!API_SCOPE_PATTERN.test(scope.name) || (SUPPORTED_SCOPES as readonly string[]).includes(scope.name)) {
      throw new AppError(`Invalid API scope: ${scope.name}`, 400, "validation_error");
    }
  }
  const ttl = input.accessTokenTtlSeconds;
  if (ttl !== undefined && (!Number.isInteger(ttl) || ttl < RESOURCE_TTL_MIN || ttl > RESOURCE_TTL_MAX)) {
    throw new AppError("Token lifetime must be 60 to 3600 seconds", 400, "validation_error");
  }
  const set: Record<string, unknown> = { name: input.name };
  if (input.scopes) set.scopes = input.scopes.map((s) => ({ name: s.name, description: s.description ?? "" }));
  if (ttl !== undefined) set.accessTokenTtlSeconds = ttl;
  if (input.allowedClientIds) set.allowedClientIds = [...new Set(input.allowedClientIds)];
  if (input.machineGrants) {
    const ids = input.machineGrants.map((g) => g.clientId);
    if (new Set(ids).size !== ids.length) throw new AppError("One machine grant per app", 400, "validation_error");
    // Only the API's own scopes can be granted.
    const defined = new Set((input.scopes ?? (await ApiResource.findOne({ identifier: input.identifier }).lean())?.scopes ?? []).map((s) => s.name));
    for (const grant of input.machineGrants) {
      const unknown = grant.scopes.filter((s) => !defined.has(s));
      if (unknown.length) throw new AppError(`Not a scope of this API: ${unknown.join(" ")}`, 400, "validation_error");
    }
    set.machineGrants = input.machineGrants.map((g) => ({ clientId: g.clientId, scopes: [...new Set(g.scopes)] }));
  }
  if (input.status) set.status = input.status;
  return ApiResource.findOneAndUpdate({ identifier: input.identifier }, { $set: set }, { upsert: true, returnDocument: "after" }).lean<ApiResourceDocument>();
}
