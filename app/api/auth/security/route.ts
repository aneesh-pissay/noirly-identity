import { NextRequest } from "next/server";
import { z } from "zod";
import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import { AppError, errorResponse } from "@/lib/api/errors";
import { withDb } from "@/lib/api/with-db";
import { enforceCsrfForCookieAuth, enforceRateLimit, readJsonBody, requestMeta } from "@/lib/api/request";
import { recordEvent } from "@/lib/audit/event-log";
import { assertKeepsAWayIn } from "@/lib/account/identities";
import type { IdentityAction } from "@/lib/audit/chain";
import { jsonResponse } from "@/lib/security/headers";
import { beginTotp, confirmTotp, RECOVERY_CODES_LOW, replaceRecoveryCodes, verifyTotpOrRecovery } from "@/lib/security/mfa";
import { registerPasskey, registrationOptions } from "@/lib/security/passkeys";
import { revokeOtherCredentials, securitySession } from "@/lib/security/security-session";
import { Mfa, Passkey } from "@/models/SecurityCredential";
import { describeAuthenticator, type AuthenticatorKind } from "@/lib/security/authenticators";
import { assertKeepsSecondFactor, mfaRequirement, setAccountMfaRequired } from "@/lib/security/factors";
import { enrollmentState } from "@/lib/security/enrollment";

const schema = z.object({
  action: z.enum(["totp-start", "totp-confirm", "totp-disable", "passkey-options", "passkey-register", "passkey-delete", "passkey-rename", "recovery-replace", "mfa-required"]),
  code: z.string().trim().max(32).optional(), token: z.string().max(128).optional(),
  name: z.string().trim().min(1).max(80).default("Passkey"), credentialId: z.string().max(2048).optional(),
  kind: z.enum(["passkey", "security_key"]).default("passkey"),
  required: z.boolean().optional(),
  response: z.object({ id: z.string().min(1).max(2048), rawId: z.string().min(1).max(2048), type: z.literal("public-key"), response: z.object({ clientDataJSON: z.string().min(1).max(16384) }).passthrough(), clientExtensionResults: z.record(z.string(), z.unknown()) }).passthrough().optional(),
});

export async function GET() {
  try { return await withDb(async () => {
    const { ctx } = await securitySession();
    const mfa = await Mfa.findOne({ userId: ctx.userId }).lean();
    const keys = await Passkey.find({ userId: ctx.userId }).sort({ createdAt: 1 }).lean();
    return jsonResponse({
      totpEnabled: Boolean(mfa?.enabled),
      totpEnabledAt: mfa?.enabled && mfa.enabledAt ? mfa.enabledAt.toISOString() : null,
      totpLastUsedAt: mfa?.enabled && mfa.lastUsedAt ? mfa.lastUsedAt.toISOString() : null,
      ...(await mfaRequirement(ctx.userId).then(({ required, sources }) => ({ mfaRequired: required, mfaSources: sources }))),
      enrollment: await enrollmentState(ctx.userId),
      recoveryCodesRemaining: mfa?.recoveryHashes.length ?? 0,
      recoveryCodesLow: Boolean(mfa?.enabled) && (mfa?.recoveryHashes.length ?? 0) <= RECOVERY_CODES_LOW,
      passkeys: keys.map((key) => ({
        id: key.credentialId,
        name: key.name,
        addedAt: key.createdAt.toISOString(),
        lastUsedAt: key.lastUsedAt ? key.lastUsedAt.toISOString() : null,
        ...describeAuthenticator({ kind: (key.kind ?? "passkey") as AuthenticatorKind, aaguid: key.aaguid, attestationFormat: key.attestationFormat, synced: key.synced, standalone: key.standalone }),
      })),
    });
  }); } catch (error) { return errorResponse(error); }
}

export async function POST(request: NextRequest) {
  try { return await withDb(async () => {
    await enforceRateLimit(request, "security-settings", 15, 300);
    await enforceCsrfForCookieAuth(request);
    const parsed = schema.safeParse(await readJsonBody(request));
    if (!parsed.success) throw new AppError("Invalid security request", 400, "invalid_request");
    const body = parsed.data;
    // Renaming changes nothing about how anyone signs in, so it doesn't need a fresh sign-in.
    const { ctx, user } = await securitySession(body.action !== "passkey-rename");
    const sessionId = ctx.session._id.toString();
    const meta = requestMeta(request);
    // Every change below signs out everywhere else, which the event says.
    const log = (action: IdentityAction, data?: Record<string, unknown>) => recordEvent({ action, subjectId: ctx.userId, request: meta, data: { ...data, otherSessionsSignedOut: true } });
    switch (body.action) {
      case "totp-start": return jsonResponse(await beginTotp(ctx.userId, user.email));
      case "totp-confirm": {
        const recoveryCodes = await confirmTotp(ctx.userId, body.code ?? "");
        await revokeOtherCredentials(ctx.userId, sessionId);
        await log("mfa.totp_enabled", { recoveryCodes: recoveryCodes.length });
        return jsonResponse({ recoveryCodes });
      }
      case "totp-disable": {
        await assertKeepsSecondFactor(ctx.userId, { totp: true });
        const factor = await verifyTotpOrRecovery(ctx.userId, body.code ?? "");
        await Mfa.deleteOne({ userId: ctx.userId });
        await revokeOtherCredentials(ctx.userId, sessionId);
        await log("mfa.totp_disabled", { confirmedWith: factor });
        return jsonResponse({ ok: true });
      }
      case "mfa-required": {
        const required = Boolean(body.required);
        await setAccountMfaRequired(ctx.userId, required);
        await recordEvent({ action: "mfa.requirement_changed", subjectId: ctx.userId, request: meta, data: { required } });
        return jsonResponse({ ok: true });
      }
      case "recovery-replace": {
        const recoveryCodes = await replaceRecoveryCodes(ctx.userId);
        await recordEvent({ action: "mfa.recovery_codes_replaced", subjectId: ctx.userId, request: meta, data: { count: recoveryCodes.length } });
        return jsonResponse({ recoveryCodes });
      }
      case "passkey-options": return jsonResponse(await registrationOptions(ctx.userId, user.email, sessionId, body.kind));
      case "passkey-register": {
        if (!body.response || !body.token) throw new AppError("Missing passkey response", 400, "invalid_request");
        const added = await registerPasskey(ctx.userId, sessionId, body.token, body.response as unknown as RegistrationResponseJSON, body.name);
        await revokeOtherCredentials(ctx.userId, sessionId);
        await log("passkey.added", { name: body.name, kind: added.kind, standalone: added.standalone });
        return jsonResponse({ ok: true, ...added });
      }
      case "passkey-delete": {
        if (!body.credentialId) throw new AppError("Missing passkey", 400, "invalid_request");
        // Never the last way in: a passkey-only account keeps its last passkey (second-step-only keys aren't a way in).
        if (await Passkey.exists({ userId: ctx.userId, credentialId: body.credentialId, standalone: { $ne: false } })) await assertKeepsAWayIn(ctx.userId, { passkeys: 1 });
        // And never the last second step on an account that requires one.
        if (await Passkey.exists({ userId: ctx.userId, credentialId: body.credentialId })) await assertKeepsSecondFactor(ctx.userId, { keys: 1 });
        const removed = await Passkey.findOneAndDelete({ userId: ctx.userId, credentialId: body.credentialId }).lean();
        await revokeOtherCredentials(ctx.userId, sessionId);
        if (removed) await log("passkey.removed", { name: removed.name, kind: removed.kind ?? "passkey" });
        return jsonResponse({ ok: true });
      }
      case "passkey-rename": {
        if (!body.credentialId) throw new AppError("Missing passkey", 400, "invalid_request");
        const before = await Passkey.findOneAndUpdate({ userId: ctx.userId, credentialId: body.credentialId }, { $set: { name: body.name } }).lean();
        if (!before) throw new AppError("Passkey not found", 404, "not_found");
        // A new name changes no way in: nobody is signed out.
        if (before.name !== body.name) await recordEvent({ action: "passkey.renamed", subjectId: ctx.userId, request: meta, data: { from: before.name, name: body.name, kind: before.kind ?? "passkey" } });
        return jsonResponse({ ok: true });
      }
    }
  }); } catch (error) { return errorResponse(error); }
}
