import { describe, expect, it } from "vitest";
import { NextRequest } from "next/server";
import { GET as describeConsent } from "@/app/api/oauth/consent/describe/route";
import { listAppAccess, noteTokenIssued } from "@/lib/account/app-access";
import { formatGrantLines, formatScopeLines, parseGrantLines, parseScopeLines } from "@/lib/oauth/resource-form";
import { saveApiResource } from "@/lib/oauth/resources";
import { describeScopesWithApis } from "@/lib/oauth/scope-descriptions";
import { createTestClient, createTestUser } from "./helpers";

const LEDGER = "https://api.ledger.noirly.test";

async function ledger(allowed: string[] = []) {
  return saveApiResource({
    identifier: LEDGER,
    name: "Ledger",
    scopes: [{ name: "ledger.read", description: "See your transactions" }, { name: "ledger.write", description: "" }],
    allowedClientIds: allowed,
  });
}

describe("what API scopes mean, in words", () => {
  it("describes an API's own scopes by its name and their descriptions, after the usual ones", async () => {
    await ledger();
    expect(await describeScopesWithApis(["openid", "email", "ledger.read", "ledger.write", "mystery"])).toEqual([
      "That it's you, by your Noirly account ID",
      "Your primary email address and whether it's confirmed",
      "Ledger: See your transactions",
      "Ledger: ledger.write",
      "mystery",
    ]);
    // Limited to the APIs a request names.
    expect(await describeScopesWithApis(["ledger.read"], ["https://api.other.noirly.test"])).toEqual(["ledger.read"]);
  });

  it("shows the consent page the app's name and those words, only for a real app at its own address", async () => {
    const { client } = await createTestClient();
    await ledger([client.clientId]);
    const ask = (params: Record<string, string>) => describeConsent(new NextRequest(`http://localhost:3000/api/oauth/consent/describe?${new URLSearchParams(params)}`));
    const ok = await ask({ client_id: client.clientId, redirect_uri: client.redirectUris[0]!, scope: "openid ledger.read", resource: LEDGER });
    expect(await ok.json()).toEqual({ app: "Test App (Development)", canSee: ["That it's you, by your Noirly account ID", "Ledger: See your transactions"] });
    expect((await ask({ client_id: client.clientId, redirect_uri: "https://evil.example.com/cb", scope: "openid" })).status).toBe(400);
    expect((await ask({ client_id: "nobody", redirect_uri: client.redirectUris[0]!, scope: "openid" })).ok).toBe(false);
  });

  it("describes them on the account page's app list too", async () => {
    const { user } = await createTestUser();
    const { client } = await createTestClient();
    await ledger([client.clientId]);
    await noteTokenIssued(user._id, client.clientId, "openid ledger.read");
    const [app] = await listAppAccess(String(user._id));
    expect(app?.canSee).toEqual(["That it's you, by your Noirly account ID", "Ledger: See your transactions"]);
  });
});

describe("the admin APIs form", () => {
  it("reads and writes scope and machine grant lines", () => {
    const scopes = parseScopeLines("ledger.read: See your transactions\n\n  ledger.write  \nledger.audit: Read: the audit log");
    expect(scopes).toEqual([
      { name: "ledger.read", description: "See your transactions" },
      { name: "ledger.write", description: "" },
      { name: "ledger.audit", description: "Read: the audit log" },
    ]);
    expect(parseScopeLines(formatScopeLines(scopes))).toEqual(scopes);

    const grants = parseGrantLines("ledger-sync: ledger.read, ledger.write\nreporter:\nbare");
    expect(grants).toEqual([
      { clientId: "ledger-sync", scopes: ["ledger.read", "ledger.write"] },
      { clientId: "reporter", scopes: [] },
      { clientId: "bare", scopes: [] },
    ]);
    expect(parseGrantLines(formatGrantLines(grants))).toEqual(grants);
  });
});
