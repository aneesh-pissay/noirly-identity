import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { requireSpacesClient } from "@/lib/spaces/integration-auth";
import { listSpacesForUser } from "@/lib/spaces/space-service";

type Params = { params: Promise<{ sub: string }> };

/** For apps: the spaces a person (by Identity `sub`) belongs to, with their role. */
export async function GET(request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      await requireSpacesClient(request);
      const { sub } = await params;
      return jsonResponse({ spaces: await listSpacesForUser(sub) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
