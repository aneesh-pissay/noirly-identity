import { isBlockedUser } from "@/lib/auth/user-policy";
import { AppError } from "@/lib/api/errors";
import { getSessionTokenFromCookies } from "@/lib/security/cookies";
import { validateSession, revokeAllUserSessions } from "@/lib/sessions/session-service";
import { AccessToken } from "@/models/AccessToken";
import { RefreshToken } from "@/models/RefreshToken";
import { Session } from "@/models/Session";
import { User } from "@/models/User";
import { SecurityChallenge } from "@/models/SecurityCredential";

export async function securitySession(recent = false) {
  const ctx = await validateSession(await getSessionTokenFromCookies());
  const user = ctx ? await User.findById(ctx.userId).lean() : null;
  if (!ctx || !user || (user.status !== "active" || isBlockedUser(user)) || !user.emailVerified) throw new AppError("Sign in required", 401, "unauthorized");
  if (recent && Date.now() - ctx.session.createdAt.getTime() > 5 * 60_000) throw new AppError("Sign in again before changing security settings", 403, "reauth_required");
  return { ctx, user };
}

export async function revokeOtherCredentials(userId: string, sessionId: string) {
  const now = new Date();
  await revokeAllUserSessions(userId, sessionId);
  await AccessToken.updateMany({ userId, revokedAt: null }, { $set: { revokedAt: now } });
  await RefreshToken.updateMany({ userId, revokedAt: null }, { $set: { revokedAt: now } });
  await SecurityChallenge.deleteMany({ userId });
  await Session.updateOne({ _id: sessionId, userId }, { $set: { securityVerifiedAt: now } });
}
