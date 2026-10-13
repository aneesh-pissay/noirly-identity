import { NextRequest } from "next/server";
import { z } from "zod";
import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import { AppError, errorResponse } from "@/lib/api/errors";
import { withDb } from "@/lib/api/with-db";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody } from "@/lib/api/request";
import { jsonResponse } from "@/lib/security/headers";
import { beginTotp, confirmTotp, verifyTotpOrRecovery } from "@/lib/security/mfa";
import { registerPasskey, registrationOptions } from "@/lib/security/passkeys";
import { revokeOtherCredentials, securitySession } from "@/lib/security/security-session";
import { Mfa, Passkey } from "@/models/SecurityCredential";

const schema = z.object({
  action: z.enum(["totp-start", "totp-confirm", "totp-disable", "passkey-options", "passkey-register", "passkey-delete"]),
  code: z.string().trim().max(32).optional(), token: z.string().max(128).optional(),
  name: z.string().trim().min(1).max(80).default("Passkey"), credentialId: z.string().max(2048).optional(),
  response: z.object({ id: z.string().min(1).max(2048), rawId: z.string().min(1).max(2048), type: z.literal("public-key"), response: z.object({ clientDataJSON: z.string().min(1).max(16384) }).passthrough(), clientExtensionResults: z.record(z.string(), z.unknown()) }).passthrough().optional(),
});

export async function GET() {
  try { return await withDb(async () => {
    const { ctx } = await securitySession();
    const mfa = await Mfa.findOne({ userId: ctx.userId }).lean();
    const keys = await Passkey.find({ userId: ctx.userId }).select("credentialId name createdAt").lean();
    return jsonResponse({ totpEnabled: Boolean(mfa?.enabled), recoveryCodesRemaining: mfa?.recoveryHashes.length ?? 0, passkeys: keys.map((key) => ({ id: key.credentialId, name: key.name })) });
  }); } catch (error) { return errorResponse(error); }
}

export async function POST(request: NextRequest) {
  try { return await withDb(async () => {
    await enforceRateLimit(request, "security-settings", 15, 300);
    await enforceCsrfForCookieAuth(request);
    const parsed = schema.safeParse(await readJsonBody(request));
    if (!parsed.success) throw new AppError("Invalid security request", 400, "invalid_request");
    const body = parsed.data;
    const { ctx, user } = await securitySession(true);
    const sessionId = ctx.session._id.toString();
    switch (body.action) {
      case "totp-start": return jsonResponse(await beginTotp(ctx.userId, user.email));
      case "totp-confirm": {
        const recoveryCodes = await confirmTotp(ctx.userId, body.code ?? "");
        await revokeOtherCredentials(ctx.userId, sessionId);
        return jsonResponse({ recoveryCodes });
      }
      case "totp-disable":
        await verifyTotpOrRecovery(ctx.userId, body.code ?? "");
        await Mfa.deleteOne({ userId: ctx.userId });
        await revokeOtherCredentials(ctx.userId, sessionId);
        return jsonResponse({ ok: true });
      case "passkey-options": return jsonResponse(await registrationOptions(ctx.userId, user.email, sessionId));
      case "passkey-register":
        if (!body.response || !body.token) throw new AppError("Missing passkey response", 400, "invalid_request");
        await registerPasskey(ctx.userId, sessionId, body.token, body.response as unknown as RegistrationResponseJSON, body.name);
        await revokeOtherCredentials(ctx.userId, sessionId);
        return jsonResponse({ ok: true });
      case "passkey-delete": {
        if (!body.credentialId) throw new AppError("Missing passkey", 400, "invalid_request");
        // Never strand a Google-only account without any sign-in method: Google remains available.
        await Passkey.deleteOne({ userId: ctx.userId, credentialId: body.credentialId });
        await revokeOtherCredentials(ctx.userId, sessionId);
        return jsonResponse({ ok: true });
      }
    }
  }); } catch (error) { return errorResponse(error); }
}
