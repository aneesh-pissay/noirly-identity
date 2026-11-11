import { Schema, Types, model, models, type Model } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { IDENTITY_ACTIONS } from "@/lib/audit/chain";
import { getEnv } from "@/lib/config/env";
import { sendEmail } from "@/lib/email/email-service";
import { buildNoticeEmail } from "@/lib/email/templates";
import { consumeRateLimit } from "@/lib/security/shared-rate-limit";

/**
 * Alerts on chosen events, for admins: a rule names actions (exact, or a
 * family like "account.") and who to email. Every event written to the log
 * (lib/audit/event-log.ts), in any stream, is matched against the rules;
 * each rule sends at most 20 emails an hour so a flood can't flood inboxes.
 */

type RuleDoc = { _id: Types.ObjectId; name: string; actions: string[]; emails: string[]; enabled: boolean; createdBy: Types.ObjectId; createdAt: Date };
const ruleSchema = new Schema({
  name: { type: String, required: true, trim: true },
  actions: { type: [String], required: true },
  emails: { type: [String], required: true },
  enabled: { type: Boolean, default: true },
  createdBy: { type: Schema.Types.ObjectId, ref: "User", required: true },
  createdAt: { type: Date, default: Date.now },
});
export const AuditAlertRule: Model<RuleDoc> = (models.AuditAlertRule as never) || model("AuditAlertRule", ruleSchema, "audit_alert_rules");

export type AlertRuleView = { id: string; name: string; actions: string[]; emails: string[]; enabled: boolean };
const view = (r: RuleDoc): AlertRuleView => ({ id: String(r._id), name: r.name, actions: r.actions, emails: r.emails, enabled: r.enabled });

const PER_RULE_PER_HOUR = 20;
const CACHE_MS = 60_000;
let cache: { at: number; rules: RuleDoc[] } | null = null;
export function resetAlertRuleCache() {
  cache = null;
}

function validActions(actions: string[]) {
  const clean = [...new Set(actions.map((a) => a.trim()).filter(Boolean))];
  for (const action of clean) {
    const ok = action.endsWith(".") ? IDENTITY_ACTIONS.some((a) => a.startsWith(action)) : (IDENTITY_ACTIONS as readonly string[]).includes(action);
    if (!ok) throw new AppError(`Unknown action: ${action}`, 400, "invalid_request");
  }
  if (!clean.length) throw new AppError("Choose at least one action", 400, "invalid_request");
  return clean;
}

export async function listAlertRules() {
  return (await AuditAlertRule.find({}).sort({ createdAt: 1 }).lean<RuleDoc[]>()).map(view);
}

export async function saveAlertRule(adminId: string, input: { id?: string; name: string; actions: string[]; emails: string[]; enabled?: boolean }) {
  const name = input.name.trim();
  if (!name || name.length > 80) throw new AppError("Name the rule", 400, "invalid_request");
  const emails = [...new Set(input.emails.map((e) => e.trim().toLowerCase()).filter(Boolean))];
  if (!emails.length || emails.length > 10 || emails.some((e) => !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e))) throw new AppError("Give 1 to 10 email addresses", 400, "invalid_request");
  const set = { name, actions: validActions(input.actions), emails, enabled: input.enabled ?? true };
  const saved = input.id
    ? await AuditAlertRule.findOneAndUpdate({ _id: Types.ObjectId.isValid(input.id) ? new Types.ObjectId(input.id) : null }, { $set: set }, { returnDocument: "after" }).lean<RuleDoc>()
    : (await AuditAlertRule.create({ ...set, createdBy: new Types.ObjectId(adminId) })).toObject() as RuleDoc;
  if (!saved) throw new AppError("Rule not found", 404, "not_found");
  resetAlertRuleCache();
  return view(saved);
}

export async function deleteAlertRule(id: string) {
  if (!Types.ObjectId.isValid(id)) throw new AppError("Rule not found", 404, "not_found");
  await AuditAlertRule.deleteOne({ _id: new Types.ObjectId(id) });
  resetAlertRuleCache();
}

const matches = (rule: RuleDoc, action: string) => rule.actions.some((a) => (a.endsWith(".") ? action.startsWith(a) : a === action));

/** Called for every event written: emails the recipients of each enabled rule it matches. */
export async function notifyAlertRules(event: { stream: string; action: string; at: string; actorId: string | null; subjectId: string | null; clientId: string | null; ipAddress: string | null }) {
  if (!cache || Date.now() - cache.at > CACHE_MS) cache = { at: Date.now(), rules: await AuditAlertRule.find({ enabled: true }).lean<RuleDoc[]>() };
  for (const rule of cache.rules.filter((r) => matches(r, event.action))) {
    const limit = await consumeRateLimit(`audit-alert:${String(rule._id)}`, PER_RULE_PER_HOUR, 3600);
    if (!limit.allowed) continue;
    const url = new URL("/admin/audit", getEnv().APP_URL);
    url.searchParams.set("action", event.action);
    if (event.subjectId) url.searchParams.set("subjectId", event.subjectId);
    for (const to of rule.emails) {
      await sendEmail({
        to,
        ...buildNoticeEmail({
          subject: `[Noirly audit] ${rule.name}: ${event.action}`,
          paragraphs: [
            `${event.action} at ${event.at} in ${event.stream}.`,
            [event.actorId && `by ${event.actorId}`, event.subjectId && `about account ${event.subjectId}`, event.clientId && `app ${event.clientId}`, event.ipAddress && `from ${event.ipAddress}`].filter(Boolean).join(", ") || "No more detail.",
          ],
          action: { label: "Open in the audit log", url: url.toString() },
        }),
        meta: { kind: "audit-alert" },
      }).catch(() => undefined);
    }
  }
}
