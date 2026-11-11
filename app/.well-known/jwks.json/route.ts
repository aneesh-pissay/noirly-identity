import { errorResponse } from "@/lib/api/errors";
import { withDb } from "@/lib/api/with-db";
import { getJwks } from "@/lib/oidc/keys";
import { jsonResponse } from "@/lib/security/headers";

export async function GET() {
  try {
    const jwks = await withDb(() => getJwks());
    const response = jsonResponse(jwks);
    response.headers.set("Cache-Control", "public, max-age=3600");
    return response;
  } catch (error) {
    return errorResponse(error);
  }
}
