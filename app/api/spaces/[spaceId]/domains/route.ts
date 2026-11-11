import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { spacesUser } from "@/lib/spaces/http";
import { addDomain, listDomains, removeDomain, setDomainPolicy, verifyDomain } from "@/lib/spaces/domains";

type Params = { params: Promise<{ spaceId: string }> };

/** The space's domains, with the TXT record each needs (members see them; owners manage them). */
export async function GET(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: false });
      const { spaceId } = await params;
      return jsonResponse({ domains: await listDomains(userId, spaceId) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}

const bodySchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("add"), domain: z.string().min(1).max(253) }),
  z.object({ action: z.literal("verify"), domain: z.string().min(1).max(253) }),
  z.object({ action: z.literal("policy"), domain: z.string().min(1).max(253), policy: z.enum(["invite_only", "auto_join"]) }),
  z.object({ action: z.literal("remove"), domain: z.string().min(1).max(253) }),
]);

/** Owners: add a domain, verify it (DNS TXT), set who may join through it, or remove it. */
export async function POST(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: true });
      const { spaceId } = await params;
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Enter a domain", 400, "invalid_request");
      const body = parsed.data;
      if (body.action === "add") await addDomain(userId, spaceId, body.domain);
      if (body.action === "verify") await verifyDomain(userId, spaceId, body.domain);
      if (body.action === "policy") await setDomainPolicy(userId, spaceId, body.domain, body.policy);
      if (body.action === "remove") await removeDomain(userId, spaceId, body.domain);
      return jsonResponse({ domains: await listDomains(userId, spaceId) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
