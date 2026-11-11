import { afterEach, describe, expect, it, vi } from "vitest";
import { downloadDataExport, requestDataExport, retryDataExports } from "@/lib/account/data-export";
import { noteTokenIssued } from "@/lib/account/app-access";
import { OAuthClient } from "@/models/OAuthClient";
import { createTestClient, createTestUser } from "./helpers";

afterEach(() => vi.restoreAllMocks());

describe("personal data export across apps", () => {
  it("bundles Identity's data with each app's answer, retrying apps that fail", async () => {
    const { user } = await createTestUser();
    const id = String(user._id);
    const { client } = await createTestClient();
    await OAuthClient.updateOne({ clientId: client.clientId }, { $set: { dataExportUri: "https://app.example.com/export" } });
    await noteTokenIssued(id, client.clientId, "openid email");

    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response("down", { status: 503 }));
    const started = await requestDataExport(id);
    expect(started.status).toBe("collecting");
    await expect(downloadDataExport(id, started.id)).rejects.toMatchObject({ status: 409 });
    const [, init] = fetchMock.mock.calls[0]!;
    expect((init as RequestInit).headers).toMatchObject({ "content-type": "application/secevent+jwt" });

    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ notes: 3 }), { status: 200 }));
    expect(await retryDataExports()).toBe(0);
    const bundle = await downloadDataExport(id, started.id);
    expect(bundle.identity).toBeTruthy();
    expect(Object.values(bundle.apps)).toEqual([{ notes: 3 }]);

    // Someone else can't download it; asking again the same day is refused.
    const { user: other } = await createTestUser({ email: "other@example.com" });
    await expect(downloadDataExport(String(other._id), started.id)).rejects.toMatchObject({ status: 404 });
    await expect(requestDataExport(id)).rejects.toMatchObject({ status: 429 });
  });
});
