import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { getSsoEnforcement, setSsoEnforcement } from "@/lib/federation/enforcement";
import { deleteProvider, listProviders, saveProvider } from "@/lib/federation/providers";
import { jsonResponse } from "@/lib/security/headers";
import { spacesUser } from "@/lib/spaces/http";

type Params = { params: Promise<{ spaceId: string }> };

/** The space's identity providers and SSO enforcement (owners, or admins with the domains area). */
export async function GET(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: false });
      const { spaceId } = await params;
      return jsonResponse({ providers: await listProviders(userId, spaceId), enforcement: await getSsoEnforcement(userId, spaceId) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}

const name = z.string().max(300);
const providerSchema = z.object({
  id: z.string().length(24).optional(),
  name: z.string().min(1).max(80),
  protocol: z.enum(["oidc", "saml"]),
  preset: z.enum(["generic", "entra", "okta"]).optional(),
  enabled: z.boolean().optional(),
  domains: z.array(z.string().max(253)).min(1).max(20),
  jit: z.boolean().optional(),
  oidc: z.object({ issuer: z.string().max(500).optional(), tenant: z.string().max(100).optional(), oktaDomain: z.string().max(200).optional(), clientId: z.string().min(1).max(300), clientSecret: z.string().max(1000).nullable().optional() }).optional(),
  saml: z.object({ idpEntityId: z.string().max(500).optional(), ssoUrl: z.string().max(2000).optional(), certificates: z.array(z.string().max(20_000)).max(5).optional(), metadataXml: z.string().max(500_000).optional(), metadataUrl: z.string().max(2000).nullable().optional() }).optional(),
  mapping: z.object({
    email: name.optional(),
    firstName: name.optional(),
    lastName: name.optional(),
    groups: name.optional(),
    roles: z.array(z.object({ group: name, role: z.enum(["admin", "member"]) })).max(50).optional(),
    teams: z.array(z.object({ group: name, teamId: z.string().length(24) })).max(50).optional(),
  }).optional(),
});

const bodySchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("save"), provider: providerSchema }),
  z.object({ action: z.literal("delete"), id: z.string().length(24) }),
  z.object({ action: z.literal("enforcement"), enforced: z.boolean().optional(), breakGlassEmails: z.array(z.string().max(254)).max(3).optional() }),
]);

/** Save or delete a provider, or change enforcement and break-glass accounts. */
export async function POST(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: true });
      const { spaceId } = await params;
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Invalid single sign-on settings", 400, "invalid_request");
      const body = parsed.data;
      if (body.action === "save") {
        const { id, ...input } = body.provider;
        await saveProvider(userId, spaceId, input, id);
      } else if (body.action === "delete") {
        await deleteProvider(userId, spaceId, body.id);
      } else {
        await setSsoEnforcement(userId, spaceId, { enforced: body.enforced, breakGlassEmails: body.breakGlassEmails });
      }
      return jsonResponse({ providers: await listProviders(userId, spaceId), enforcement: await getSsoEnforcement(userId, spaceId) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
