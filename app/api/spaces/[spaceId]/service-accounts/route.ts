import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { readJsonBody, requestMeta } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { spacesUser } from "@/lib/spaces/http";
import { createServiceAccount, disableServiceAccount, listServiceAccounts, rotateServiceAccountSecret } from "@/lib/authz/service-accounts";

type Params = { params: Promise<{ spaceId: string }> };

/** The organization's service accounts (admins with the access area). */
export async function GET(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: false });
      const { spaceId } = await params;
      return jsonResponse({ serviceAccounts: await listServiceAccounts(userId, spaceId) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}

const bodySchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("create"), name: z.string().min(1).max(60) }),
  z.object({ action: z.literal("rotate"), serviceAccountId: z.string().length(24) }),
  z.object({ action: z.literal("disable"), serviceAccountId: z.string().length(24) }),
]);

/** Create (the secret is shown once), rotate its secret, or disable it. */
export async function POST(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: true });
      const { spaceId } = await params;
      const parsed = bodySchema.safeParse(await readJsonBody(request));
      if (!parsed.success) throw new AppError("Invalid request", 400, "invalid_request");
      const body = parsed.data;
      const meta = requestMeta(request);
      if (body.action === "create") return jsonResponse(await createServiceAccount(userId, spaceId, body.name, meta), { status: 201 });
      if (body.action === "rotate") return jsonResponse(await rotateServiceAccountSecret(userId, spaceId, body.serviceAccountId));
      return jsonResponse({ serviceAccount: await disableServiceAccount(userId, spaceId, body.serviceAccountId, meta) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
