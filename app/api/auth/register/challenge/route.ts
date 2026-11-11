import { NextRequest } from "next/server";
import { errorResponse } from "@/lib/api/errors";
import { enforceRateLimit } from "@/lib/api/request";
import { jsonResponse } from "@/lib/security/headers";
import { issueSignupChallenge } from "@/lib/security/signup-protection";

/** A proof-of-work challenge for the sign-up form (lib/security/signup-protection.ts). */
export async function GET(request: NextRequest) {
  try {
    await enforceRateLimit(request, "signup-challenge", 30, 60);
    return jsonResponse(issueSignupChallenge());
  } catch (error) {
    return errorResponse(error);
  }
}
