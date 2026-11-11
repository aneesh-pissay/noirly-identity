import { isBlockedUser } from "@/lib/auth/user-policy";
import { NextRequest } from "next/server";
import { z } from "zod";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { AppError, errorResponse } from "@/lib/api/errors";
import { withDb } from "@/lib/api/with-db";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { recordEvent } from "@/lib/audit/event-log";
import type { SignInMethod } from "@/lib/audit/chain";
import { jsonResponse } from "@/lib/security/headers";
import { setSessionCookie } from "@/lib/security/cookies";
import { checkFactorRate, MFA_COOKIE, RECOVERY_CODES_LOW, remindRecoveryCodesLow, verifyTotpOrRecovery } from "@/lib/security/mfa";
import { authenticatePasskey, authenticationOptions } from "@/lib/security/passkeys";
import { hashToken } from "@/lib/security/crypto";
import { createSession } from "@/lib/sessions/session-service";
import { Session } from "@/models/Session";
import { toPublicUser } from "@/lib/auth/user-mapper";
import { mintMobileTokens, requirePublicMobileClient } from "@/lib/mobile/mint-tokens";
import { Mfa, SecurityChallenge } from "@/models/SecurityCredential";
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
    let factor: SignInMethod;
    if (body.action === "passkey-verify") {
      if (!body.response) throw new AppError("Missing passkey response", 400, "invalid_request");
      challenge = await authenticatePasskey(token, body.response as unknown as AuthenticationResponseJSON);
      factor = "passkey";
    } else {
      const existing = await SecurityChallenge.findOne({ tokenHash: hashToken(token), purpose: "login-mfa", expiresAt: { $gt: new Date() } }).lean();
      if (!existing?.userId) throw new AppError("Verification expired", 401, "invalid_challenge");
      if (existing.emailCodeHash) {
        // An adaptive second step: the code emailed to the account (lib/security/mfa.ts).
        await checkFactorRate(existing.userId.toString());
        if (hashToken(`email-code:${(body.code ?? "").trim()}`) !== existing.emailCodeHash) throw new AppError("That code isn't right", 400, "invalid_code");
        factor = "email_code";
      } else {
        factor = await verifyTotpOrRecovery(existing.userId.toString(), body.code ?? "");
      }
      challenge = await SecurityChallenge.findOneAndDelete({ _id: existing._id, expiresAt: { $gt: new Date() } }).lean();
    }
    if (!challenge?.userId) throw new AppError("Verification already used", 401, "invalid_challenge");
    const user = await User.findById(challenge.userId);
    if (!user || (user.status !== "active" || isBlockedUser(user)) || !user.emailVerified) throw new AppError("Account unavailable", 401, "unauthorized");
    user.lastLoginAt = new Date();
    await user.save();
    const meta = requestMeta(request);
    // A passkey on its own is a whole sign-in; a step-up adds to how the session was signed in; otherwise it's the first step's method, then this one.
    const methods: SignInMethod[] = challenge.purpose === "passkey-login"
      ? [factor]
      : challenge.priorMethods?.length
        ? [...new Set([...(challenge.priorMethods as SignInMethod[]), factor])]
        : [(challenge.method as SignInMethod | null) ?? "password", factor];
    if (challenge.stepUpSessionId) {
      // A step-up strengthens the session the person already has, so apps signed in through it stay signed in.
      const now = new Date();
      const upgraded = await Session.updateOne({ _id: challenge.stepUpSessionId, userId: user._id, revokedAt: null, expiresAt: { $gt: now } }, { $set: { methods, authenticatedAt: now, securityVerifiedAt: now } });
      if (upgraded.modifiedCount !== 1) throw new AppError("Your session ended. Sign in again.", 401, "unauthorized");
      await recordEvent({ action: "auth.stepped_up", subjectId: user._id, request: meta, data: { methods } });
      const response = jsonResponse({ ok: true });
      response.cookies.set(MFA_COOKIE, "", { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict", path: "/", maxAge: 0 });
      return response;
    }
    const session = await createSession({ userId: user._id, ...meta, securityVerified: true, methods });
    if (factor === "recovery_code") {
      const left = (await Mfa.findOne({ userId: user._id }).select("recoveryHashes").lean())?.recoveryHashes.length ?? 0;
      await recordEvent({ action: "mfa.recovery_code_used", subjectId: user._id, clientId: challenge.clientId ?? null, request: meta, data: { remaining: left } });
      if (left <= RECOVERY_CODES_LOW) await remindRecoveryCodesLow(user.email, left);
    }
    await recordEvent({ action: "auth.signed_in", subjectId: user._id, clientId: challenge.clientId ?? null, request: meta, data: { methods } });
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

/** Which kind of code the waiting sign-in needs: from an authenticator, or emailed (adaptive). */
export async function GET(request: NextRequest) {
  try { return await withDb(async () => {
    const token = request.cookies.get(MFA_COOKIE)?.value;
    const existing = token ? await SecurityChallenge.findOne({ tokenHash: hashToken(token), purpose: "login-mfa", expiresAt: { $gt: new Date() } }).select("emailCodeHash").lean() : null;
    return jsonResponse({ via: existing?.emailCodeHash ? "email" : "authenticator" });
  }); } catch (error) { return errorResponse(error); }
}
