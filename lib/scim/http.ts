import { NextResponse, type NextRequest } from "next/server";
import { AppError } from "@/lib/api/errors";
import { withDb } from "@/lib/api/with-db";
import { authenticateScim } from "@/lib/scim/tokens";

/** SCIM 2.0 (RFC 7643/7644) plumbing: auth, JSON in and out, errors in SCIM's shape. */

export const SCHEMA = {
  user: "urn:ietf:params:scim:schemas:core:2.0:User",
  group: "urn:ietf:params:scim:schemas:core:2.0:Group",
  list: "urn:ietf:params:scim:api:messages:2.0:ListResponse",
  patch: "urn:ietf:params:scim:api:messages:2.0:PatchOp",
  error: "urn:ietf:params:scim:api:messages:2.0:Error",
} as const;

/** A SCIM error: `scimType` per RFC 7644 §3.12. */
export class ScimError extends Error {
  constructor(public status: number, message: string, public scimType?: string) {
    super(message);
  }
}

export function scimJson(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new NextResponse(status === 204 ? null : JSON.stringify(body), { status, headers: { "content-type": "application/scim+json; charset=utf-8", "cache-control": "no-store", ...headers } });
}

export function scimRoute<P>(handler: (ctx: { request: NextRequest; organizationId: string; params: P }) => Promise<NextResponse>) {
  return async (request: NextRequest, context: { params: Promise<P> }) => {
    try {
      return await withDb(async () => {
        const { organizationId } = await authenticateScim(request.headers.get("authorization"));
        return handler({ request, organizationId, params: await context.params });
      });
    } catch (error) {
      if (error instanceof ScimError) return scimJson({ schemas: [SCHEMA.error], status: String(error.status), detail: error.message, ...(error.scimType ? { scimType: error.scimType } : {}) }, error.status);
      if (error instanceof AppError) {
        const scimType = error.status === 409 ? "uniqueness" : error.status === 400 ? "invalidValue" : undefined;
        return scimJson({ schemas: [SCHEMA.error], status: String(error.status), detail: error.message, ...(scimType ? { scimType } : {}) }, error.status, error.status === 401 ? { "www-authenticate": 'Bearer realm="scim"' } : {});
      }
      console.error("SCIM request failed", error instanceof Error ? error.message : error);
      return scimJson({ schemas: [SCHEMA.error], status: "500", detail: "Something went wrong" }, 500);
    }
  };
}

export async function readScimBody(request: NextRequest): Promise<Record<string, unknown>> {
  const text = await request.text();
  if (text.length > 1_000_000) throw new ScimError(413, "Request too large");
  try {
    const body = JSON.parse(text) as unknown;
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error();
    return body as Record<string, unknown>;
  } catch {
    throw new ScimError(400, "The body must be a JSON object", "invalidSyntax");
  }
}

/** One `attr eq "value"` filter, which is what provisioning clients send. */
export function parseFilter(filter: string | null): { attr: string; value: string } | null {
  if (!filter) return null;
  const m = /^\s*([A-Za-z][\w.]*(?:\[value eq "[^"]*"\])?)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$/i.exec(filter);
  if (!m) throw new ScimError(400, "Only `attribute eq \"value\"` filters are supported", "invalidFilter");
  return { attr: m[1]!.toLowerCase(), value: m[2]!.replace(/\\(.)/g, "$1") };
}

export function paging(request: NextRequest) {
  const p = request.nextUrl.searchParams;
  const startIndex = Math.max(1, Number.parseInt(p.get("startIndex") ?? "1", 10) || 1);
  const count = Math.min(200, Math.max(0, Number.parseInt(p.get("count") ?? "100", 10) || 0));
  return { startIndex, count };
}

export const listResponse = (resources: unknown[], total: number, startIndex: number) => ({ schemas: [SCHEMA.list], totalResults: total, startIndex, itemsPerPage: resources.length, Resources: resources });

/** PATCH operations, in either dialect (Entra's capitalized ops and string booleans, Okta's value objects). */
export type PatchOp = { op: "add" | "remove" | "replace"; path: string | null; value: unknown };
export function patchOps(body: Record<string, unknown>): PatchOp[] {
  const ops = body.Operations;
  if (!Array.isArray(ops) || !ops.length) throw new ScimError(400, "Operations are required", "invalidSyntax");
  return ops.map((raw) => {
    const o = raw as { op?: unknown; path?: unknown; value?: unknown };
    const op = String(o.op ?? "").toLowerCase();
    if (op !== "add" && op !== "remove" && op !== "replace") throw new ScimError(400, `Unknown op ${String(o.op)}`, "invalidSyntax");
    return { op, path: typeof o.path === "string" && o.path ? o.path : null, value: o.value };
  });
}

export const truthy = (v: unknown) => v === true || (typeof v === "string" && v.toLowerCase() === "true");
