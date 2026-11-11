import { describe, expect, it } from "vitest";
import { noteTokenIssued } from "@/lib/account/app-access";
import { reviewClaims, trimScopes } from "@/lib/oauth/claim-review";
import { OAuthClient } from "@/models/OAuthClient";
import { createTestClient, createTestUser } from "./helpers";

describe("claim minimization review", () => {
  it("flags scopes nobody granted once an app has settled, and trims them", async () => {
    const { user } = await createTestUser();
    const { user: admin } = await createTestUser({ email: "admin@example.com" });
    const { client } = await createTestClient();
    await OAuthClient.updateOne({ clientId: client.clientId }, { $set: { allowedScopes: ["openid", "email", "profile", "phone"] } });
    await noteTokenIssued(String(user._id), client.clientId, "openid email");

    let [review] = await reviewClaims(client.clientId);
    expect(review).toMatchObject({ settling: true, unused: [] });
    expect(review!.granted).toMatchObject({ openid: 1, email: 1 });

    await OAuthClient.collection.updateOne({ clientId: client.clientId }, { $set: { createdAt: new Date(Date.now() - 60 * 86_400_000) } });
    [review] = await reviewClaims(client.clientId);
    expect(review).toMatchObject({ settling: false, unused: ["profile", "phone"] });

    const trimmed = await trimScopes(client.clientId, ["profile", "phone", "openid"], String(admin._id));
    expect(trimmed.allowed).toEqual(["openid", "email"]);
    expect(trimmed.unused).toEqual([]);
    await expect(trimScopes("missing", ["email"], String(admin._id))).rejects.toMatchObject({ status: 404 });
  });
});
