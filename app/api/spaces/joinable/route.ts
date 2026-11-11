import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { withDb } from "@/lib/api/with-db";
import { jsonResponse } from "@/lib/security/headers";
import { spacesUser } from "@/lib/spaces/http";
import { joinableSpaces } from "@/lib/spaces/domains";

/** Spaces you may join without an invitation, through your work address's verified domain. */
export async function GET(request: NextRequest) {
  try {
    return await withDb(async () => {
      const { userId } = await spacesUser(request, { change: false });
      return jsonResponse({ spaces: await joinableSpaces(userId) });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
