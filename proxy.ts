import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { securePageResponse, rejectCrossOriginMutation } from "@/lib/security/request";

export function proxy(request: NextRequest) {
  if (request.nextUrl.pathname.endsWith(".map")) return new NextResponse(null, { status: 404 });
  // OIDC token and mobile routes do not use browser cookies for authentication.
  // Google One Tap additionally verifies a server-issued nonce cookie.
  if (request.nextUrl.pathname.startsWith("/api/auth/")) {
    const rejection = rejectCrossOriginMutation(request, process.env.APP_URL);
    if (rejection) return rejection;
  }
  return securePageResponse(request);
}
export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)", "/_next/:path*.map"] };
