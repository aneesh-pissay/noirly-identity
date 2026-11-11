import { describe, expect, it } from "vitest";
import { decodeJwt } from "jose";
import { accessibilityOf, canonicalLocale, canonicalTimeZone, preferenceClaims } from "@/lib/account/preferences";
import { listEvents } from "@/lib/audit/event-log";
import { updateUserProfile } from "@/lib/auth/auth-service";
import { createAuthorizationCode } from "@/lib/oauth/authorize";
import { exchangeAuthorizationCode } from "@/lib/oauth/token";
import { buildDiscoveryDocument } from "@/lib/oidc/discovery";
import { buildUserInfo } from "@/lib/oidc/userinfo";
import { generateSecureToken } from "@/lib/security/crypto";
import { updateProfileSchema } from "@/lib/validation/schemas";
import { createAuthedSession, createTestClient, createTestUser, pkceChallenge } from "./helpers";

async function tokensFor(userId: string, scope: string) {
  const { client, clientSecret } = await createTestClient();
  const { token: sessionToken } = await createAuthedSession(userId);
  const verifier = generateSecureToken(32);
  const { code } = await createAuthorizationCode({ sessionToken, clientId: client.clientId, redirectUri: client.redirectUris[0]!, scope, codeChallenge: pkceChallenge(verifier), codeChallengeMethod: "S256" });
  return exchangeAuthorizationCode({ code, redirectUri: client.redirectUris[0]!, clientId: client.clientId, clientSecret, codeVerifier: verifier, authorizationHeader: null });
}

describe("preference rules", () => {
  it("accepts real language tags and time zones, in their canonical spelling", () => {
    expect(canonicalLocale("en-in")).toBe("en-IN");
    expect(canonicalLocale("hi-IN")).toBe("hi-IN");
    expect(canonicalLocale("not a locale!")).toBeNull();
    expect(canonicalTimeZone("asia/kolkata")).toBe("Asia/Kolkata");
    expect(canonicalTimeZone("Mars/Olympus_Mons")).toBeNull();
  });

  it("validates them on the way in", () => {
    expect(updateProfileSchema.parse({ locale: "en-in", zoneinfo: "asia/kolkata" })).toEqual({ locale: "en-IN", zoneinfo: "Asia/Kolkata" });
    expect(updateProfileSchema.safeParse({ zoneinfo: "Nowhere/Land" }).success).toBe(false);
    expect(updateProfileSchema.safeParse({ accessibility: { textSize: "huge" } }).success).toBe(false);
    expect(updateProfileSchema.parse({ locale: null })).toEqual({ locale: null });
  });

  it("fills in defaults and only claims what's set", () => {
    expect(accessibilityOf(null)).toEqual({ motion: "system", contrast: "system", textSize: "default" });
    expect(preferenceClaims({ locale: null, zoneinfo: "Asia/Kolkata", accessibility: { textSize: "large" } })).toEqual({
      zoneinfo: "Asia/Kolkata",
      noirly_accessibility: { motion: "system", contrast: "system", textSize: "large" },
    });
  });
});

describe("preferences", () => {
  it("are saved with the profile and shared with apps under the profile scope", async () => {
    const { user } = await createTestUser();
    const id = String(user._id);
    const { token } = await createAuthedSession(id);
    const saved = await updateUserProfile(token, updateProfileSchema.parse({ locale: "hi-IN", zoneinfo: "Asia/Kolkata", accessibility: { motion: "reduce", textSize: "larger" } }));
    expect(saved).toMatchObject({ locale: "hi-IN", zoneinfo: "Asia/Kolkata", accessibility: { motion: "reduce", contrast: "system", textSize: "larger" } });
    // Only what changed, not the values.
    const [event] = (await listEvents({ action: "account.profile_updated" })).events;
    expect(event!.data).toEqual({ fields: expect.arrayContaining(["locale", "zoneinfo", "accessibility"]) });

    const tokens = await tokensFor(id, "openid profile email");
    expect(decodeJwt(tokens.id_token)).toMatchObject({ locale: "hi-IN", zoneinfo: "Asia/Kolkata", noirly_accessibility: { motion: "reduce", textSize: "larger" } });
    expect(await buildUserInfo(tokens.access_token)).toMatchObject({ locale: "hi-IN", zoneinfo: "Asia/Kolkata" });

    const emailOnly = await tokensFor(id, "openid email");
    expect(await buildUserInfo(emailOnly.access_token)).not.toHaveProperty("locale");
    expect(buildDiscoveryDocument().claims_supported).toEqual(expect.arrayContaining(["locale", "zoneinfo", "noirly_accessibility"]));
  });

  it("go back to the device's when cleared, and log nothing when nothing changed", async () => {
    const { user } = await createTestUser();
    const { token } = await createAuthedSession(String(user._id));
    await updateUserProfile(token, updateProfileSchema.parse({ locale: "en-GB" }));
    const cleared = await updateUserProfile(token, updateProfileSchema.parse({ locale: null, accessibility: { motion: "system" } }));
    expect(cleared.locale).toBeNull();
    const events = (await listEvents({ action: "account.profile_updated" })).events;
    expect(events.map((e) => e.data)).toEqual([{ fields: ["locale"] }, { fields: ["locale"] }]);
  });
});
