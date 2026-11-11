/**
 * Attribute-based conditions on a role assignment. Every condition must hold
 * for the assignment to count. Attributes come from the member's attributes in
 * the organization (department, region, anything the organization sets) and
 * from the moment of the check:
 * - `time` `between` "09:00-18:00" (in the organization's time zone, or UTC);
 * - `weekday` `in` "mon,tue,wed,thu,fri";
 * - `device` `eq` "trusted": the sign-in used a passkey or a second step;
 * - `acr` `eq` a level (lib/auth/acr.ts);
 * - `country` `in` "IN,GB": where the session was signed in, from the edge.
 * Operators: `eq`, `neq`, `in`, `not_in`, `between` (times only).
 */

export type Condition = { attribute: string; op: string; value: string };

export type CheckContext = {
  now?: Date;
  /** The organization's time zone for `time` and `weekday`; UTC without one. */
  timeZone?: string;
  acr?: string | null;
  deviceTrusted?: boolean;
  country?: string | null;
};

export const CONDITION_OPS = ["eq", "neq", "in", "not_in", "between"] as const;
const WEEKDAYS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

const list = (value: string) => value.split(",").map((v) => v.trim().toLowerCase()).filter(Boolean);

function localTime(now: Date, timeZone?: string) {
  const parts = new Intl.DateTimeFormat("en-GB", { timeZone: timeZone || "UTC", hour: "2-digit", minute: "2-digit", weekday: "short", hourCycle: "h23" }).formatToParts(now);
  const get = (type: string) => parts.find((p) => p.type === type)?.value ?? "";
  return { minutes: Number(get("hour")) * 60 + Number(get("minute")), weekday: get("weekday").toLowerCase().slice(0, 3) };
}

function toMinutes(hhmm: string) {
  const match = /^(\d{1,2}):(\d{2})$/.exec(hhmm.trim());
  if (!match) return null;
  return Number(match[1]) * 60 + Number(match[2]);
}

/** Checks one condition; returns why it failed, or null when it holds. */
export function failedCondition(condition: Condition, attributes: Record<string, string>, context: CheckContext): string | null {
  const { attribute, op, value } = condition;
  const now = context.now ?? new Date();
  const local = localTime(now, context.timeZone);
  let actual: string | null;
  switch (attribute) {
    case "time": {
      const [from, to] = value.split("-").map(toMinutes);
      if (op !== "between" || from === null || to === null || from === undefined || to === undefined) return `time needs "between" and HH:MM-HH:MM`;
      const inside = from <= to ? local.minutes >= from && local.minutes < to : local.minutes >= from || local.minutes < to;
      return inside ? null : `outside ${value}`;
    }
    case "weekday":
      actual = local.weekday;
      break;
    case "device":
      actual = context.deviceTrusted ? "trusted" : "untrusted";
      break;
    case "acr":
      actual = context.acr ?? null;
      break;
    case "country":
      actual = context.country?.toLowerCase() ?? null;
      break;
    default:
      actual = attributes[attribute]?.toLowerCase() ?? null;
  }
  const want = value.toLowerCase();
  const holds =
    op === "eq" ? actual === want
      : op === "neq" ? actual !== want
        : op === "in" ? actual !== null && list(want).includes(actual)
          : op === "not_in" ? actual === null || !list(want).includes(actual)
            : false;
  return holds ? null : `${attribute} is ${actual ?? "not set"}, needs ${op} ${value}`;
}

/** Validates conditions when they're set. */
export function validateConditions(conditions: Condition[]): Condition[] {
  for (const c of conditions) {
    if (!/^[a-z][a-z0-9_]{0,40}$/.test(c.attribute)) throw new Error(`Invalid attribute: ${c.attribute}`);
    if (!(CONDITION_OPS as readonly string[]).includes(c.op)) throw new Error(`Invalid operator: ${c.op}`);
    if (c.attribute === "time" && (c.op !== "between" || !/^\d{1,2}:\d{2}-\d{1,2}:\d{2}$/.test(c.value))) throw new Error("time needs between HH:MM-HH:MM");
    if (c.attribute === "weekday" && !list(c.value).every((d) => WEEKDAYS.includes(d))) throw new Error("weekday takes sun..sat");
    if (!c.value || c.value.length > 200) throw new Error("Each condition needs a value");
  }
  return conditions;
}
