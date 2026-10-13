import { NextRequest } from "next/server";
import { enforceRateLimit } from "@/lib/api/request";
import { errorResponse } from "@/lib/api/errors";
import { generateSecureToken } from "@/lib/security/crypto";
import { jsonResponse } from "@/lib/security/headers";

export async function GET(request: NextRequest) {
  try {
    await enforceRateLimit(request, "google-nonce", 30, 300);
    const nonce = generateSecureToken();
    const production = process.env.NODE_ENV === "production";
    const response = jsonResponse({ nonce });
    response.cookies.set(production ? "__Host-noirly_google_nonce" : "noirly_google_nonce", nonce, { httpOnly: true, secure: production, sameSite: "strict", path: "/", maxAge: 300 });
    return response;
  } catch (error) { return errorResponse(error); }
}
