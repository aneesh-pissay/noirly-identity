import { describe, expect, it } from "vitest";
import { issueClientCredentialsToken } from "@/lib/oauth/client-credentials";
import { listOAuthClients, updateAppClient } from "@/lib/oauth/client-admin";
import { introspectToken } from "@/lib/oauth/introspect";
import { saveApiResource } from "@/lib/oauth/resources";
import { authenticateClient } from "@/lib/oauth/token";
import { OAuthClient } from "@/models/OAuthClient";
import { createTestClient } from "./helpers";

const signIn = (clientId: string, clientSecret: string) => authenticateClient({ clientId, clientSecret, authorizationHeader: null });
const refused = (promise: Promise<unknown>) => expect(promise).rejects.toMatchObject({ error: "invalid_client" });

describe("client secret rotation", () => {
  it("keeps the old secret working through the overlap, noting when it's used, then not after", async () => {
    const { client, clientSecret: oldSecret } = await createTestClient();
    const { clientSecret: newSecret, client: view } = await updateAppClient(client.clientId, { rotateSecret: true, secretOverlapSeconds: 3600 });
    expect(newSecret).toBeTruthy();
    expect(view.previousSecretExpiresAt).toBeTruthy();
    expect(view.previousSecretLastUsedAt).toBeNull();

    await expect(signIn(client.clientId, newSecret!)).resolves.toBeTruthy();
    await expect(signIn(client.clientId, oldSecret)).resolves.toBeTruthy();
    const [listed] = await listOAuthClients();
    expect(listed?.previousSecretLastUsedAt).toBeTruthy();
    await refused(signIn(client.clientId, "neither"));

    // Once the overlap ends, only the new one works, and the old one isn't shown.
    await OAuthClient.updateOne({ clientId: client.clientId }, { $set: { previousSecretExpiresAt: new Date(Date.now() - 1000) } });
    await refused(signIn(client.clientId, oldSecret));
    await expect(signIn(client.clientId, newSecret!)).resolves.toBeTruthy();
    expect((await listOAuthClients())[0]?.previousSecretExpiresAt).toBeNull();
  });

  it("overlaps for a day unless told otherwise, and never more than a week", async () => {
    const { client } = await createTestClient();
    const { client: view } = await updateAppClient(client.clientId, { rotateSecret: true });
    const left = new Date(view.previousSecretExpiresAt!).getTime() - Date.now();
    expect(left).toBeGreaterThan(86_400_000 - 60_000);
    expect(left).toBeLessThanOrEqual(86_400_000);
    await expect(updateAppClient(client.clientId, { rotateSecret: true, secretOverlapSeconds: 8 * 86_400 })).rejects.toMatchObject({ status: 400 });
  });

  it("retires the old secret early on request", async () => {
    const { client, clientSecret: oldSecret } = await createTestClient();
    await updateAppClient(client.clientId, { rotateSecret: true });
    const { client: view, clientSecret } = await updateAppClient(client.clientId, { dropPreviousSecret: true });
    expect(clientSecret).toBeNull();
    expect(view.previousSecretExpiresAt).toBeNull();
    await refused(signIn(client.clientId, oldSecret));
  });

  it("for a leaked secret: stops it at once and revokes the app's own tokens", async () => {
    const { client, clientSecret: leaked } = await createTestClient();
    await saveApiResource({ identifier: "https://api.x.noirly.test", name: "X", scopes: [{ name: "x.read" }], machineGrants: [{ clientId: client.clientId, scopes: ["x.read"] }] });
    const stored = (await OAuthClient.findOne({ clientId: client.clientId }))!;
    const machine = await issueClientCredentialsToken({ client: stored, resource: "https://api.x.noirly.test" });
    expect((await introspectToken(machine.access_token, "any")).active).toBe(true);

    const { clientSecret: fresh } = await updateAppClient(client.clientId, { rotateSecret: true, secretOverlapSeconds: 0, revokeMachineTokens: true });
    await refused(signIn(client.clientId, leaked));
    await expect(signIn(client.clientId, fresh!)).resolves.toBeTruthy();
    expect(await introspectToken(machine.access_token, "any")).toEqual({ active: false });
  });

  it("drops a pending old secret when an app becomes public", async () => {
    const { client, clientSecret: oldSecret } = await createTestClient();
    await updateAppClient(client.clientId, { rotateSecret: true });
    const { client: view } = await updateAppClient(client.clientId, { clientType: "public" });
    expect(view.previousSecretExpiresAt).toBeNull();
    const stored = await OAuthClient.findOne({ clientId: client.clientId }).select("+previousSecretHash").lean();
    expect(stored?.previousSecretHash).toBeNull();
    void oldSecret;
  });
});
