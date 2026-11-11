import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { orgStream } from "@/lib/audit/chain";
import { recordEvent } from "@/lib/audit/event-log";
import { normalizeEmail } from "@/lib/auth/user-mapper";
import { deactivateMember, reactivateMember, requireMembersAdmin } from "@/lib/directory/lifecycle";
import { inviteToSpace } from "@/lib/spaces/invitations";
import { changeMemberRole, removeMember, type SpaceRole } from "@/lib/spaces/space-service";
import { SpaceTeam } from "@/models/SpaceTeam";

/**
 * Bulk invitation, CSV import and bulk management. Each person is handled
 * on their own: one bad row doesn't stop the rest, and the result says what
 * happened to each. Every change goes through the same checks as doing it
 * one at a time (who may invite owners, last owner, and so on).
 */

const MAX_ROWS = 500;
const ROLES = new Set(["member", "admin", "owner"]);

export type RowResult = { row: number; email?: string; userId?: string; ok: boolean; result: string };

/** Invites many addresses with one role. */
export async function bulkInvite(actorId: string, spaceId: string, emails: string[], role: SpaceRole): Promise<RowResult[]> {
  await requireMembersAdmin(spaceId, actorId);
  const list = [...new Set(emails.map((e) => e.trim()).filter(Boolean))];
  if (list.length > MAX_ROWS) throw new AppError(`Up to ${MAX_ROWS} at a time`, 400, "too_many");
  const results: RowResult[] = [];
  for (const [i, raw] of list.entries()) results.push(await inviteOne(actorId, spaceId, i + 1, raw, role));
  await summary(actorId, spaceId, "invite", results);
  return results;
}

async function inviteOne(actorId: string, spaceId: string, row: number, raw: string, role: SpaceRole): Promise<RowResult> {
  const email = normalizeEmail(raw);
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return { row, email: raw, ok: false, result: "Not an email address" };
  try {
    await inviteToSpace(actorId, spaceId, email, role);
    return { row, email, ok: true, result: "Invited" };
  } catch (error) {
    return { row, email, ok: false, result: error instanceof AppError ? error.message : "Couldn't invite" };
  }
}

/** Splits CSV text into rows (quotes, commas and newlines inside quotes handled). */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { cell += '"'; i++; }
      else if (c === '"') quoted = false;
      else cell += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") { row.push(cell); cell = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(cell); cell = "";
      if (row.some((x) => x.trim())) rows.push(row);
      row = [];
    } else cell += c;
  }
  row.push(cell);
  if (row.some((x) => x.trim())) rows.push(row);
  return rows;
}

/**
 * CSV import: a header row with `email`, and optionally `role` (member,
 * admin, owner) and `teams` (team names, separated by `;`). Everyone listed
 * is invited with their role; their teams are applied when they accept.
 */
export async function importCsv(actorId: string, spaceId: string, text: string): Promise<RowResult[]> {
  await requireMembersAdmin(spaceId, actorId);
  if (text.length > 1_000_000) throw new AppError("That file is too large", 400, "too_large");
  const [header, ...rows] = parseCsv(text.replace(/^﻿/, ""));
  if (!header) throw new AppError("The file is empty", 400, "invalid_request");
  const col = (name: string) => header.findIndex((h) => h.trim().toLowerCase() === name);
  const emailCol = col("email");
  if (emailCol < 0) throw new AppError("The first row must name the columns, including `email`", 400, "invalid_request");
  if (rows.length > MAX_ROWS) throw new AppError(`Up to ${MAX_ROWS} rows at a time`, 400, "too_many");
  const roleCol = col("role");
  const teamsCol = col("teams");
  const teams = new Map((await SpaceTeam.find({ organizationId: new Types.ObjectId(spaceId) }).select("name").lean()).map((t) => [t.name.toLowerCase(), t._id]));

  const results: RowResult[] = [];
  for (const [i, cells] of rows.entries()) {
    const row = i + 2;
    const role = (roleCol >= 0 ? cells[roleCol]?.trim().toLowerCase() : "") || "member";
    if (!ROLES.has(role)) { results.push({ row, email: cells[emailCol], ok: false, result: `Unknown role "${role}"` }); continue; }
    const wanted = teamsCol >= 0 ? (cells[teamsCol] ?? "").split(";").map((t) => t.trim()).filter(Boolean) : [];
    const unknown = wanted.filter((t) => !teams.has(t.toLowerCase()));
    if (unknown.length) { results.push({ row, email: cells[emailCol], ok: false, result: `Unknown team: ${unknown.join(", ")}` }); continue; }
    const result = await inviteOne(actorId, spaceId, row, cells[emailCol] ?? "", role as SpaceRole);
    if (result.ok && wanted.length) {
      const { SpaceInvitation } = await import("@/models/SpaceInvitation");
      await SpaceInvitation.updateOne({ organizationId: new Types.ObjectId(spaceId), email: result.email, acceptedAt: null, revokedAt: null }, { $set: { teamIds: wanted.map((t) => teams.get(t.toLowerCase())!) } });
      result.result = `Invited, to join ${wanted.join(", ")}`;
    }
    results.push(result);
  }
  await summary(actorId, spaceId, "import", results);
  return results;
}

export type BulkAction = { action: "remove" } | { action: "role"; role: SpaceRole } | { action: "deactivate" } | { action: "reactivate" } | { action: "add_to_team"; teamId: string } | { action: "remove_from_team"; teamId: string };

/** One action on many members. */
export async function bulkManage(actorId: string, spaceId: string, userIds: string[], action: BulkAction): Promise<RowResult[]> {
  await requireMembersAdmin(spaceId, actorId);
  const ids = [...new Set(userIds)];
  if (ids.length > MAX_ROWS) throw new AppError(`Up to ${MAX_ROWS} at a time`, 400, "too_many");
  let team: Types.ObjectId | null = null;
  if (action.action === "add_to_team" || action.action === "remove_from_team") {
    const found = Types.ObjectId.isValid(action.teamId) ? await SpaceTeam.findOne({ _id: new Types.ObjectId(action.teamId), organizationId: new Types.ObjectId(spaceId) }).select("_id").lean() : null;
    if (!found) throw new AppError("Team not found", 404, "not_found");
    team = found._id;
  }
  const results: RowResult[] = [];
  for (const [i, userId] of ids.entries()) {
    try {
      if (!Types.ObjectId.isValid(userId)) throw new AppError("Not a member", 404, "not_found");
      if (action.action === "remove") await removeMember(actorId, spaceId, userId);
      else if (action.action === "role") await changeMemberRole(actorId, spaceId, userId, action.role);
      else if (action.action === "deactivate") await deactivateMember(spaceId, userId, { actorId, via: "bulk" });
      else if (action.action === "reactivate") await reactivateMember(spaceId, userId, { actorId, via: "bulk" });
      else {
        const { OrganizationMembership } = await import("@/models/OrganizationMembership");
        if (!(await OrganizationMembership.exists({ organizationId: new Types.ObjectId(spaceId), userId: new Types.ObjectId(userId) }))) throw new AppError("Not a member", 404, "not_found");
        await SpaceTeam.updateOne({ _id: team! }, action.action === "add_to_team" ? { $addToSet: { memberIds: new Types.ObjectId(userId) } } : { $pull: { memberIds: new Types.ObjectId(userId) } });
      }
      results.push({ row: i + 1, userId, ok: true, result: "Done" });
    } catch (error) {
      results.push({ row: i + 1, userId, ok: false, result: error instanceof AppError ? error.message : "Failed" });
    }
  }
  await summary(actorId, spaceId, action.action, results);
  return results;
}

async function summary(actorId: string, spaceId: string, action: string, results: RowResult[]) {
  await recordEvent({ action: "directory.bulk_action", stream: orgStream(spaceId), actorId, subjectId: null, data: { organizationId: spaceId, action, done: results.filter((r) => r.ok).length, failed: results.filter((r) => !r.ok).length } });
}
