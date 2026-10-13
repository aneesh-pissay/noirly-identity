import { isBlockedUser } from "@/lib/auth/user-policy";
import { NextRequest } from "next/server";
import { z } from "zod";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { AppError, errorResponse } from "@/lib/api/errors";
import { withDb } from "@/lib/api/with-db";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody } from "@/lib/api/request";
import { jsonResponse } from "@/lib/security/headers";
import { setSessionCookie } from "@/lib/security/cookies";
import { MFA_COOKIE, verifyTotpOrRecovery } from "@/lib/security/mfa";
import { authenticatePasskey, authenticationOptions } from "@/lib/security/passkeys";
import { hashToken } from "@/lib/security/crypto";
import { createSession } from "@/lib/sessions/session-service";
import { getClientIp } from "@/lib/security/rate-limit";
import { toPublicUser } from "@/lib/auth/user-mapper";
import { mintMobileTokens, requirePublicMobileClient } from "@/lib/mobile/mint-tokens";
import { SecurityChallenge } from "@/models/SecurityCredential";
import { User } from "@/models/User";

const schema = z.object({ action: z.enum(["code", "passkey-options", "passkey-login-options", "passkey-verify"]),
  code: z.string().trim().max(32).optional(), challenge: z.string().min(20).max(128).optional(),
  response: z.object({ id: z.string().min(1).max(2048), rawId: z.string().min(1).max(2048), type: z.literal("public-key"), response: z.object({ clientDataJSON: z.string().min(1).max(16384) }).passthrough(), clientExtensionResults: z.record(z.string(), z.unknown()) }).passthrough().optional() });

export async function POST(request: NextRequest) {
  try { return await withDb(async () => {
    await enforceRateLimit(request, "mfa-verify", 25, 300);
    const parsed = schema.safeParse(await readJsonBody(request));
    if (!parsed.success) throw new AppError("Invalid verification request", 400, "invalid_request");
    const body = parsed.data;
    const token = body.challenge ?? request.cookies.get(MFA_COOKIE)?.value;
    // Only a challenge issued by a mobile primary-factor login may bypass cookie CSRF.
    if (body.challenge) {
      const mobile = await SecurityChallenge.exists({ tokenHash: hashToken(body.challenge), clientId: { $ne: null }, purpose: "login-mfa", expiresAt: { $gt: new Date() } });
      if (!mobile) throw new AppError("Invalid mobile verification", 401, "invalid_challenge");
    } else await enforceCsrfForCookieAuth(request);

    if (body.action === "passkey-options" || body.action === "passkey-login-options") {
      const result = await authenticationOptions(body.action === "passkey-login-options" ? undefined : token);
      const response = jsonResponse({ options: result.options });
      response.cookies.set(MFA_COOKIE, result.token!, { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict", path: "/", maxAge: 300 });
      return response;
    }
    if (!token) throw new AppError("Verification expired. Sign in again.", 401, "invalid_challenge");
    let challenge;
    if (body.action === "passkey-verify") {
      if (!body.response) throw new AppError("Missing passkey response", 400, "invalid_request");
      challenge = await authenticatePasskey(token, body.response as unknown as AuthenticationResponseJSON);
    } else {
      const existing = await SecurityChallenge.findOne({ tokenHash: hashToken(token), purpose: "login-mfa", expiresAt: { $gt: new Date() } }).lean();
      if (!existing?.userId) throw new AppError("Verification expired", 401, "invalid_challenge");
      await verifyTotpOrRecovery(existing.userId.toString(), body.code ?? "");
      challenge = await SecurityChallenge.findOneAndDelete({ _id: existing._id, expiresAt: { $gt: new Date() } }).lean();
    }
    if (!challenge?.userId) throw new AppError("Verification already used", 401, "invalid_challenge");
    const user = await User.findById(challenge.userId);
    if (!user || (user.status !== "active" || isBlockedUser(user)) || !user.emailVerified) throw new AppError("Account unavailable", 401, "unauthorized");
    user.lastLoginAt = new Date();
    await user.save();
    const session = await createSession({ userId: user._id, ipAddress: getClientIp(request), userAgent: request.headers.get("user-agent"), securityVerified: true });
    if (challenge.clientId && challenge.scope) {
      await requirePublicMobileClient(challenge.clientId);
      return jsonResponse(await mintMobileTokens({ clientId: challenge.clientId, scope: challenge.scope, nonce: challenge.nonce, sessionToken: session.token, user: toPublicUser(user) }));
    }
    const response = jsonResponse({ ok: true });
    await setSessionCookie(response, session.token);
    response.cookies.set(MFA_COOKIE, "", { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict", path: "/", maxAge: 0 });
    return response;
  }); } catch (error) { return errorResponse(error); }
}
