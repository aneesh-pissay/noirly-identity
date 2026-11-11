import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import type { Types } from "mongoose";
import { GET as authorize } from "@/app/api/oauth/authorize/route";
import { getEnv } from "@/lib/config/env";
import { generateSecureToken } from "@/lib/security/crypto";
import { assertKeepsSecondFactor, mfaRequirement, setAccountMfaRequired } from "@/lib/security/factors";
import { createSession } from "@/lib/sessions/session-service";
import { enrollmentState, MFA_GRACE_DAYS } from "@/lib/security/enrollment";
import { resetEmailProvider, setEmailProvider, type EmailMessage } from "@/lib/email/email-service";
import { User } from "@/models/User";
import { setSpaceMfaRequired } from "@/lib/spaces/space-service";
import { OAuthClient } from "@/models/OAuthClient";
import { Organization } from "@/models/Organization";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { Passkey } from "@/models/SecurityCredential";
import { createTestClient, createTestUser, pkceChallenge } from "./helpers";

const jar = vi.hoisted(() => new Map<string, string>());
vi.mock("next/headers", () => ({ cookies: async () => ({ get: (key: string) => (jar.has(key) ? { value: jar.get(key) } : undefined) }) }));
beforeEach(() => jar.clear());

async function spaceWith(members: Array<[Types.ObjectId, "owner" | "admin" | "member"]>, requireMfa = false) {
  const space = await Organization.create({ name: "Acme", slug: `acme-${generateSecureToken(4).toLowerCase()}`, requireMfa });
  for (const [userId, role] of members) await OrganizationMembership.create({ organizationId: space._id, userId, role });
  return space;
}

const addKey = (userId: Types.ObjectId) => Passkey.create({ userId, credentialId: generateSecureToken(16), publicKey: "k", counter: 0 });

function authorizeUrl(clientId: string, redirectUri: string) {
  const url = new URL("http://localhost:3000/api/oauth/authorize");
  for (const [k, v] of Object.entries({ client_id: clientId, redirect_uri: redirectUri, response_type: "code", scope: "openid", state: "st", code_challenge: pkceChallenge(generateSecureToken(32)), code_challenge_method: "S256" })) url.searchParams.set(k, v);
  return url;
}

async function signIn(userId: unknown, methods: Array<"password" | "totp">) {
  const { token } = await createSession({ userId: String(userId), methods });
  jar.set(getEnv().SESSION_COOKIE_NAME, token);
}

const where = (response: Response) => new URL(response.headers.get("location")!);

describe("what requires a second step", () => {
  it("lists the account's own setting and every space that requires one", async () => {
    const { user } = await createTestUser();
    await addKey(user._id);
    expect(await mfaRequirement(user._id)).toEqual({ required: false, sources: [] });
    await setAccountMfaRequired(String(user._id), true);
    const space = await spaceWith([[user._id, "member"]], true);
    expect(await mfaRequirement(user._id)).toEqual({ required: true, sources: [{ type: "account" }, { type: "space", id: String(space._id), name: "Acme" }] });
  });

  it("can't be turned on for an account with no second step", async () => {
    const { user } = await createTestUser();
    await expect(setAccountMfaRequired(String(user._id), true)).rejects.toMatchObject({ code: "no_second_factor" });
  });

  it("is a space admin's to turn on, once they have a second step themselves", async () => {
    const admin = (await createTestUser({ email: "admin@example.com" })).user;
    const member = (await createTestUser({ email: "member@example.com" })).user;
    const space = await spaceWith([[admin._id, "admin"], [member._id, "member"]]);
    await expect(setSpaceMfaRequired(String(member._id), String(space._id), true)).rejects.toMatchObject({ status: 403 });
    await expect(setSpaceMfaRequired(String(admin._id), String(space._id), true)).rejects.toMatchObject({ code: "no_second_factor" });
    await addKey(admin._id);
    expect(await setSpaceMfaRequired(String(admin._id), String(space._id), true)).toMatchObject({ requireMfa: true });
    // Now the member's last key, once they have one, stays.
    await addKey(member._id);
    await expect(assertKeepsSecondFactor(String(member._id), { keys: 1 })).rejects.toMatchObject({ code: "last_second_factor" });
  });
});

describe("apps and spaces that require a second step", () => {
  it("an app that requires one: set one up first, then step up", async () => {
    const { user } = await createTestUser();
    const { client } = await createTestClient();
    await OAuthClient.updateOne({ clientId: client.clientId }, { $set: { requireMfa: true } });
    await signIn(user._id, ["password"]);

    const setUp = where(await authorize(new NextRequest(authorizeUrl(client.clientId, client.redirectUris[0]!))));
    expect(setUp.pathname).toBe("/account");
    expect(setUp.searchParams.get("mfa_for")).toBe(client.clientId);
    expect(setUp.searchParams.get("return_to")).toContain("/api/oauth/authorize");

    await addKey(user._id);
    expect(where(await authorize(new NextRequest(authorizeUrl(client.clientId, client.redirectUris[0]!)))).pathname).toBe("/api/auth/step-up");
    await signIn(user._id, ["password", "totp"]);
    expect(where(await authorize(new NextRequest(authorizeUrl(client.clientId, client.redirectUris[0]!)))).searchParams.get("code")).toBeTruthy();
  });

  it("a space that requires one: its members step up for every app", async () => {
    const { user } = await createTestUser();
    const { client } = await createTestClient();
    await spaceWith([[user._id, "member"]], true);
    await addKey(user._id);
    await signIn(user._id, ["password"]);
    expect(where(await authorize(new NextRequest(authorizeUrl(client.clientId, client.redirectUris[0]!)))).pathname).toBe("/api/auth/step-up");
  });

  it("nothing required: a single step is enough", async () => {
    const { user } = await createTestUser();
    const { client } = await createTestClient();
    await signIn(user._id, ["password"]);
    expect(where(await authorize(new NextRequest(authorizeUrl(client.clientId, client.redirectUris[0]!)))).searchParams.get("code")).toBeTruthy();
  });
});

describe("getting a second step set up", () => {
  it("starts a grace period, with an email, when a space turns the requirement on", async () => {
    const sent: EmailMessage[] = [];
    setEmailProvider({ send: async (message) => { sent.push(message); } });
    try {
      const admin = (await createTestUser({ email: "admin@example.com" })).user;
      const member = (await createTestUser({ email: "member@example.com" })).user;
      await addKey(admin._id);
      const space = await spaceWith([[admin._id, "admin"], [member._id, "member"]]);
      await setSpaceMfaRequired(String(admin._id), String(space._id), true);
      // Only the member without one is told.
      expect(sent.map((m) => m.to)).toEqual(["member@example.com"]);
      const state = await enrollmentState(member._id);
      expect(state).toMatchObject({ state: "grace", daysLeft: MFA_GRACE_DAYS, spaces: ["Acme"] });
      expect(await enrollmentState(admin._id)).toEqual({ state: "enrolled" });
    } finally {
      resetEmailProvider();
    }
  });

  it("nudges once per session in the grace period, then lets the person through", async () => {
    const { user } = await createTestUser();
    const { client } = await createTestClient();
    await spaceWith([[user._id, "member"]], true);
    await signIn(user._id, ["password"]);
    const nudge = where(await authorize(new NextRequest(authorizeUrl(client.clientId, client.redirectUris[0]!))));
    expect(nudge.pathname).toBe("/account");
    expect(nudge.searchParams.get("enroll")).toBe("grace");
    // "Not now": the same session goes on to the app.
    expect(where(await authorize(new NextRequest(authorizeUrl(client.clientId, client.redirectUris[0]!)))).searchParams.get("code")).toBeTruthy();
  });

  it("closes apps once the grace period is over, until one is set up", async () => {
    const { user } = await createTestUser();
    const { client } = await createTestClient();
    await spaceWith([[user._id, "member"]], true);
    await User.updateOne({ _id: user._id }, { $set: { mfaGraceUntil: new Date(Date.now() - 1000) } });
    await signIn(user._id, ["password"]);
    const blocked = where(await authorize(new NextRequest(authorizeUrl(client.clientId, client.redirectUris[0]!))));
    expect(blocked.pathname).toBe("/account");
    expect(blocked.searchParams.get("enroll")).toBe("overdue");
    expect(await enrollmentState(user._id)).toMatchObject({ state: "overdue" });
    // Set one up: the grace date is cleared, and the app asks for it.
    await addKey(user._id);
    expect(await enrollmentState(user._id)).toEqual({ state: "enrolled" });
    expect((await User.findById(user._id).lean())!.mfaGraceUntil).toBeNull();
    expect(where(await authorize(new NextRequest(authorizeUrl(client.clientId, client.redirectUris[0]!)))).pathname).toBe("/api/auth/step-up");
  });
});
