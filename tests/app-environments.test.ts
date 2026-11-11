import { describe, expect, it } from "vitest";
import { NextRequest } from "next/server";
import { GET as describeConsent } from "@/app/api/oauth/consent/describe/route";
import { listAppAccess, noteTokenIssued } from "@/lib/account/app-access";
import { addAppEnvironment, listOAuthClients, registerAppClient, updateAppClient } from "@/lib/oauth/client-admin";
import { appDisplayName, environmentClientId, inferEnvironment, redirectProblem } from "@/lib/oauth/environments";
import { authenticateClient } from "@/lib/oauth/token";
import { OAuthClient } from "@/models/OAuthClient";
import { createTestUser } from "./helpers";

describe("environment rules", () => {
  it("keep production and staging on https real hosts, and development on local ones", () => {
    expect(redirectProblem("production", ["https://crm.noirly.com/api/auth/callback/noirly", "noirlycrm://oauth"])).toBeNull();
    expect(redirectProblem("production", ["http://crm.noirly.com/cb"])).toMatch(/https/);
    expect(redirectProblem("production", ["https://localhost:3001/cb"])).toMatch(/local/);
    expect(redirectProblem("staging", ["http://127.0.0.1:3001/cb"])).toMatch(/local/);
    expect(redirectProblem("development", ["http://localhost:3001/cb", "https://crm.localhost/cb", "http://crm.test/cb", "noirlycrm://oauth"])).toBeNull();
    expect(redirectProblem("development", ["https://crm.noirly.com/cb"])).toMatch(/localhost/);
  });

  it("name client IDs and apps by environment, and work out older clients' environment", () => {
    expect(environmentClientId("noirly-crm", "production")).toBe("noirly-crm");
    expect(environmentClientId("noirly-crm", "staging")).toBe("noirly-crm-staging");
    expect(environmentClientId("noirly-crm", "development")).toBe("noirly-crm-dev");
    expect(appDisplayName("Noirly CRM", "staging")).toBe("Noirly CRM (Staging)");
    expect(appDisplayName("Noirly CRM", "production")).toBe("Noirly CRM");
    expect(inferEnvironment(["http://localhost:3001/cb"])).toBe("development");
    expect(inferEnvironment(["https://crm.noirly.com/cb", "http://localhost:3001/cb"])).toBe("production");
    expect(inferEnvironment(["noirlycrm://oauth"])).toBe("production");
  });
});

describe("app environments", () => {
  it("register production, then staging and development apart: own IDs, secrets and redirects", async () => {
    const prod = await registerAppClient({ clientId: "noirly-crm", name: "Noirly CRM", origins: ["https://crm.noirly.com"] });
    expect(prod.client).toMatchObject({ appKey: "noirly-crm", environment: "production" });

    const staging = await addAppEnvironment("noirly-crm", { environment: "staging", origins: ["https://staging.crm.noirly.com"] });
    const dev = await addAppEnvironment("noirly-crm", { environment: "development", origins: ["http://localhost:3001"] });
    expect(staging.client).toMatchObject({ clientId: "noirly-crm-staging", appKey: "noirly-crm", environment: "staging", name: "Noirly CRM", redirectUris: ["https://staging.crm.noirly.com/api/auth/callback/noirly"] });
    expect(dev.client).toMatchObject({ clientId: "noirly-crm-dev", environment: "development" });

    // Secrets are apart: each works only for its own client.
    await expect(authenticateClient({ clientId: "noirly-crm-staging", clientSecret: staging.clientSecret!, authorizationHeader: null })).resolves.toBeTruthy();
    await expect(authenticateClient({ clientId: "noirly-crm", clientSecret: staging.clientSecret!, authorizationHeader: null })).rejects.toMatchObject({ error: "invalid_client" });
    await expect(authenticateClient({ clientId: "noirly-crm-dev", clientSecret: prod.clientSecret!, authorizationHeader: null })).rejects.toMatchObject({ error: "invalid_client" });

    // One of each.
    await expect(addAppEnvironment("noirly-crm-dev", { environment: "staging", origins: ["https://other.noirly.com"] })).rejects.toMatchObject({ status: 409 });
    expect((await listOAuthClients()).map((c) => `${c.clientId}:${c.environment}`).sort()).toEqual(["noirly-crm-dev:development", "noirly-crm-staging:staging", "noirly-crm:production"]);
  });

  it("refuse redirects that don't fit the environment, on create, add and edit", async () => {
    await expect(registerAppClient({ clientId: "noirly-flow", name: "Flow", origins: ["https://localhost:4000"], environment: "production" })).rejects.toMatchObject({ status: 400 });
    await registerAppClient({ clientId: "noirly-flow", name: "Flow", origins: ["https://flow.noirly.com"], environment: "production" });
    await expect(addAppEnvironment("noirly-flow", { environment: "development", origins: ["https://flow-dev.noirly.com"] })).rejects.toMatchObject({ status: 400 });
    await expect(addAppEnvironment("noirly-flow", { environment: "staging", origins: ["http://staging.flow.noirly.com"] })).rejects.toMatchObject({ status: 400 });
    // Adding a localhost redirect to production, or relabelling it development while it points at a live site.
    await expect(updateAppClient("noirly-flow", { redirectUris: ["http://localhost:4000/cb"] })).rejects.toMatchObject({ status: 400 });
    await expect(updateAppClient("noirly-flow", { environment: "development" })).rejects.toMatchObject({ status: 400 });
    await expect(registerAppClient({ clientId: "noirly-flow", name: "Flow", origins: ["http://localhost:4000"] })).rejects.toMatchObject({ status: 400 });
  });

  it("keep older clients working as they were, until an environment is chosen", async () => {
    // A client from before, with local and live redirects together.
    await OAuthClient.create({ clientId: "legacy", name: "Legacy", description: "", redirectUris: ["http://localhost:3005/cb", "https://legacy.noirly.com/cb"], clientType: "public", status: "active" });
    expect((await listOAuthClients())[0]).toMatchObject({ appKey: "legacy", environment: "production", environmentSet: false });
    // Still editable as before.
    await updateAppClient("legacy", { redirectUris: ["http://localhost:3006/cb", "https://legacy.noirly.com/cb"] });
    // Choosing an environment applies its rules: move localhost to a development environment first.
    await expect(updateAppClient("legacy", { environment: "production" })).rejects.toMatchObject({ status: 400 });
    await updateAppClient("legacy", { redirectUris: ["https://legacy.noirly.com/cb"], environment: "production" });
    expect((await listOAuthClients())[0]).toMatchObject({ environment: "production", environmentSet: true });
    await addAppEnvironment("legacy", { environment: "development", redirectUris: ["http://localhost:3006/cb"] });
    expect((await OAuthClient.find({ appKey: "legacy" }).lean()).map((c) => c.clientId).sort()).toEqual(["legacy", "legacy-dev"]);
  });

  it("tell people which environment they're dealing with outside production", async () => {
    await registerAppClient({ clientId: "noirly-crm", name: "Noirly CRM", origins: ["https://crm.noirly.com"] });
    const dev = await addAppEnvironment("noirly-crm", { environment: "development", origins: ["http://localhost:3001"] });
    const consent = await describeConsent(new NextRequest(`http://localhost:3000/api/oauth/consent/describe?${new URLSearchParams({ client_id: "noirly-crm-dev", redirect_uri: dev.client.redirectUris[0]!, scope: "openid" })}`));
    expect((await consent.json()).app).toBe("Noirly CRM (Development)");

    const { user } = await createTestUser();
    await noteTokenIssued(user._id, "noirly-crm-dev", "openid");
    await noteTokenIssued(user._id, "noirly-crm", "openid");
    expect((await listAppAccess(String(user._id))).map((a) => a.name).sort()).toEqual(["Noirly CRM", "Noirly CRM (Development)"]);
  });
});
