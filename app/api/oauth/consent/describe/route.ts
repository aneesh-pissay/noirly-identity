import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { enforceRateLimit } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { assertExactRedirectUri, getActiveClient } from "@/lib/oauth/clients";
import { parseResourceParam } from "@/lib/oauth/resources";
import { describeScopesWithApis } from "@/lib/oauth/scope-descriptions";
import { jsonResponse } from "@/lib/security/headers";
import { appDisplayName } from "@/lib/oauth/environments";
import { environmentOf } from "@/lib/oauth/client-admin";

/**
 * What the consent page shows: the app's name, and what each requested scope
 * lets it do, in words. Only for a known app at one of its own redirect URIs,
 * so it can't be used to dress up someone else's request.
 */
export async function GET(request: NextRequest) {
  try {
    return await withDb(async () => {
      await enforceRateLimit(request, "consent-describe", 60, 60);
      const params = request.nextUrl.searchParams;
      const client = await getActiveClient(params.get("client_id") ?? "");
      assertExactRedirectUri(client, params.get("redirect_uri") ?? "");
      const scopes = [...new Set((params.get("scope") ?? "openid").split(/\s+/).filter(Boolean))];
      return jsonResponse({
        app: appDisplayName(client.name, environmentOf(client)),
        canSee: await describeScopesWithApis(scopes, parseResourceParam(params.get("resource"))),
      });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
