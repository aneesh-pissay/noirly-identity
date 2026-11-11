import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { securePageResponse, rejectCrossOriginMutation } from "@/lib/security/request";

export function proxy(request: NextRequest) {
  if (request.nextUrl.pathname.endsWith(".map")) return new NextResponse(null, { status: 404 });
  // Profile photos set their own caching and policy headers (app/api/avatars).
  if (request.nextUrl.pathname.startsWith("/api/avatars/")) return NextResponse.next();
  // OIDC token and mobile routes do not use browser cookies for authentication.
  // Google One Tap additionally verifies a server-issued nonce cookie.
  // Apple posts its answer from appleid.apple.com; the route only turns it into a GET, where the state is checked.
  const applePostBack = request.method === "POST" && request.nextUrl.pathname === "/api/auth/apple/callback";
  if (request.nextUrl.pathname.startsWith("/api/auth/") && !applePostBack) {
    const rejection = rejectCrossOriginMutation(request, process.env.APP_URL);
    if (rejection) return rejection;
  }
  return securePageResponse(request);
}
export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)", "/_next/:path*.map"] };
