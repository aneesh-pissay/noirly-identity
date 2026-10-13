import { isBlockedUser } from "@/lib/auth/user-policy";
import { randomInt } from "node:crypto";
import { NextRequest } from "next/server";
import { z } from "zod";
import { AppError, errorResponse } from "@/lib/api/errors";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody } from "@/lib/api/request";
import { withDb } from "@/lib/api/with-db";
import { getEnv } from "@/lib/config/env";
import { generateSecureToken, hashToken } from "@/lib/security/crypto";
import { jsonResponse } from "@/lib/security/headers";
import { securitySession } from "@/lib/security/security-session";
import { requirePublicMobileClient, resolveMobileScope, mintMobileTokens } from "@/lib/mobile/mint-tokens";
import { createSession } from "@/lib/sessions/session-service";
import { toPublicUser } from "@/lib/auth/user-mapper";
import { MobileBrowserLogin } from "@/models/MobileBrowserLogin";
import { User } from "@/models/User";
import { Session } from "@/models/Session";

const bodySchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("start"), client_id: z.string().min(1).max(200) }),
  z.object({ action: z.literal("poll"), token: z.string().min(20).max(128) }),
  z.object({ action: z.literal("approve"), request: z.string().min(20).max(128), code: z.string().regex(/^\d{6}$/) }),
]);

export async function POST(request: NextRequest) {
  try { return await withDb(async () => {
    const parsed = bodySchema.safeParse(await readJsonBody(request));
    if (!parsed.success) throw new AppError("Invalid browser login request", 400, "invalid_request");
    const body = parsed.data;
    await enforceRateLimit(request, `mobile-browser-${body.action}`, body.action === "poll" ? 180 : 10, 300);
    if (body.action === "start") {
      const client = await requirePublicMobileClient(body.client_id);
      const browserRequest = generateSecureToken();
      const pollToken = generateSecureToken();
      const displayCode = String(randomInt(100000, 1000000));
      await MobileBrowserLogin.create({ requestHash: hashToken(browserRequest), pollHash: hashToken(pollToken), clientId: client.clientId, scope: resolveMobileScope(client), displayCode, expiresAt: new Date(Date.now() + 5 * 60_000) });
      const url = new URL("/mobile-login", getEnv().APP_URL);
      url.searchParams.set("request", browserRequest);
      return jsonResponse({ url: url.toString(), token: pollToken, displayCode, expiresIn: 300 });
    }
    if (body.action === "approve") {
      await enforceCsrfForCookieAuth(request);
      const { ctx } = await securitySession();
      const result = await MobileBrowserLogin.updateOne({ requestHash: hashToken(body.request), displayCode: body.code, userId: null, expiresAt: { $gt: new Date() } }, { $set: { userId: ctx.userId, sessionId: ctx.session._id } });
      if (result.modifiedCount !== 1) throw new AppError("Request expired or code did not match", 400, "invalid_request");
      return jsonResponse({ ok: true });
    }
    const record = await MobileBrowserLogin.findOneAndDelete({ pollHash: hashToken(body.token), userId: { $ne: null }, expiresAt: { $gt: new Date() } }).lean();
    if (!record) {
      if (!await MobileBrowserLogin.exists({ pollHash: hashToken(body.token), expiresAt: { $gt: new Date() } })) throw new AppError("Sign-in request expired", 410, "expired_request");
      return jsonResponse({ pending: true }, { status: 202 });
    }
    const user = await User.findById(record.userId);
    const browserSession = await Session.findOne({ _id: record.sessionId, userId: record.userId, revokedAt: null, expiresAt: { $gt: new Date() } }).lean();
    if (!user || (user.status !== "active" || isBlockedUser(user)) || !user.emailVerified || !browserSession) throw new AppError("Sign in again", 401, "unauthorized");
    await requirePublicMobileClient(record.clientId);
    const session = await createSession({ userId: user._id, userAgent: request.headers.get("user-agent"), securityVerified: Boolean(browserSession.securityVerifiedAt) });
    return jsonResponse(await mintMobileTokens({ clientId: record.clientId, scope: record.scope, sessionToken: session.token, user: toPublicUser(user) }));
  }); } catch (error) { return errorResponse(error); }
}
