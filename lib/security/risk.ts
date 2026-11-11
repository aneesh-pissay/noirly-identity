import { Types } from "mongoose";
import { recordEvent } from "@/lib/audit/event-log";
import { SignInRecord } from "@/models/SignInRecord";

/**
 * Unusual sign-in detection. Each sign-in is compared with the account's
 * recent ones:
 * - `new_device`: a device (its id, or failing that its browser) never seen;
 * - `new_country`: a country never seen;
 * - `impossible_travel`: a different country from a sign-in under two hours
 *   earlier (the edge gives countries, not coordinates, so this is the
 *   honest version of "too far, too fast").
 * The first sign-in of a new account has nothing to compare with, so it's
 * never unusual. Risk: impossible travel, or a new device in a new country,
 * is high; a new country alone is medium; a new device alone is low. High
 * risk asks for a second step even when it's optional (lib/security/mfa.ts).
 */

export type RiskSignal = "new_device" | "new_country" | "impossible_travel";
export type Risk = { level: "none" | "low" | "medium" | "high"; signals: RiskSignal[] };
export type SignInContext = { deviceId?: string | null; userAgent?: string | null; place?: string | null; at?: Date };

const HISTORY = 50;
const TRAVEL_WINDOW_MS = 2 * 3600_000;

export function countryOf(place: string | null | undefined): string | null {
  const code = place?.split(",").pop()?.trim().toUpperCase();
  return code && /^[A-Z]{2}$/.test(code) ? code : null;
}

/** A short, stable form of a user agent: enough to tell browsers apart, not to fingerprint. */
function agentOf(userAgent: string | null | undefined) {
  if (!userAgent) return null;
  const browser = /(Edg|Firefox|Chrome|Safari|OPR)\/[\d]+/.exec(userAgent)?.[1] ?? "other";
  const os = /(Windows|Mac OS X|Android|iPhone|iPad|Linux)/.exec(userAgent)?.[1] ?? "other";
  return `${browser}:${os}`;
}

export async function assessSignInRisk(userId: string | Types.ObjectId, context: SignInContext): Promise<Risk> {
  const history = await SignInRecord.find({ userId: new Types.ObjectId(String(userId)) }).sort({ at: -1 }).limit(HISTORY).lean();
  if (!history.length) return { level: "none", signals: [] };
  const signals: RiskSignal[] = [];
  const at = context.at ?? new Date();
  const country = countryOf(context.place);
  const agent = agentOf(context.userAgent);

  const knownDevice = context.deviceId
    ? history.some((h) => h.deviceId === context.deviceId)
    : agent ? history.some((h) => h.agent === agent) : true;
  if (!knownDevice) signals.push("new_device");
  if (country && !history.some((h) => h.country === country)) signals.push("new_country");
  const last = history[0]!;
  if (country && last.country && last.country !== country && at.getTime() - last.at.getTime() < TRAVEL_WINDOW_MS) signals.push("impossible_travel");

  const level: Risk["level"] =
    signals.includes("impossible_travel") || (signals.includes("new_device") && signals.includes("new_country")) ? "high"
      : signals.includes("new_country") ? "medium"
        : signals.length ? "low" : "none";
  return { level, signals };
}

/**
 * Notes a completed sign-in: compares it with the history, adds it, and logs
 * an unusual one (`auth.unusual_sign_in`, which also emails the owner).
 */
export async function noteSignIn(userId: string | Types.ObjectId, context: SignInContext): Promise<Risk> {
  const risk = await assessSignInRisk(userId, context);
  await SignInRecord.create({
    userId: new Types.ObjectId(String(userId)),
    at: context.at ?? new Date(),
    deviceId: context.deviceId ?? null,
    agent: agentOf(context.userAgent),
    country: countryOf(context.place),
    signals: risk.signals,
  });
  if (risk.signals.length) {
    await recordEvent({ action: "auth.unusual_sign_in", subjectId: String(userId), actorId: null, request: { place: context.place, userAgent: context.userAgent }, data: { signals: risk.signals, level: risk.level } });
  }
  return risk;
}
