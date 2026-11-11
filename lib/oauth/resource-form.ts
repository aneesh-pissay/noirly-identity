/**
 * The admin APIs screen edits scopes and machine grants as lines of text.
 * These turn them into what POST /api/admin/resources takes and back. No
 * server code, so the screen can use them.
 */

/** "crm.read: Read your contacts", one per line; the description is optional. */
export function parseScopeLines(text: string): Array<{ name: string; description: string }> {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const at = line.indexOf(":");
      return at === -1
        ? { name: line, description: "" }
        : { name: line.slice(0, at).trim(), description: line.slice(at + 1).trim() };
    });
}

export function formatScopeLines(scopes: Array<{ name: string; description: string }>): string {
  return scopes.map((s) => (s.description ? `${s.name}: ${s.description}` : s.name)).join("\n");
}

/** "ledger-sync: ledger.read ledger.write", one app per line. */
export function parseGrantLines(text: string): Array<{ clientId: string; scopes: string[] }> {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const at = line.indexOf(":");
      const clientId = (at === -1 ? line : line.slice(0, at)).trim();
      const scopes = at === -1 ? [] : line.slice(at + 1).split(/[\s,]+/).filter(Boolean);
      return { clientId, scopes };
    });
}

export function formatGrantLines(grants: Array<{ clientId: string; scopes: string[] }>): string {
  return grants.map((g) => `${g.clientId}: ${g.scopes.join(" ")}`.trim()).join("\n");
}
