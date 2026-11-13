import { describe, expect, it } from "vitest";
import { googleProfileFromIdTokenClaims } from "@/lib/auth/google";

describe("google ID token profile", () => {
  it("maps a verified Google ID token payload", () => {
    const profile = googleProfileFromIdTokenClaims({
      sub: "gid-1",
      email: "Ada@Noirly.com",
      email_verified: true,
      given_name: "Ada",
      family_name: "Lovelace",
      name: "Ada Lovelace",
      picture: "https://example.com/a.png",
    });
    expect(profile.email).toBe("ada@noirly.com");
    expect(profile.sub).toBe("gid-1");
    expect(profile.firstName).toBe("Ada");
  });

  it("rejects unverified emails", () => {
    expect(() =>
      googleProfileFromIdTokenClaims({
        sub: "gid-1",
        email: "ada@noirly.com",
        email_verified: false,
      }),
    ).toThrow(/not verified/);
  });
});
