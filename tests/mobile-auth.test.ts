import { describe, expect, it } from "vitest";
import {
  mobileLoginWithPassword,
  mobileLogout,
  mobileRefreshTokens,
  mobileRegister,
} from "@/lib/mobile/auth";
import { AppError } from "@/lib/api/errors";
import { createTestClient, createTestUser } from "./helpers";
import { resolveAccessToken } from "@/lib/tokens/token-service";
import { User } from "@/models/User";

describe("mobile native auth", () => {
  it("rejects confidential clients", async () => {
    const { user, password } = await createTestUser({
      email: "mobile-conf@example.com",
    });
    const { client } = await createTestClient({ clientType: "confidential" });

    await expect(
      mobileLoginWithPassword(
        {
          client_id: client.clientId,
          email: user.email,
          password,
        },
        { ipAddress: "127.0.0.1", userAgent: "vitest" },
      ),
    ).rejects.toMatchObject({ code: "invalid_client" });
  });

  it("logs in a public client and returns tokens + user", async () => {
    const { user, password } = await createTestUser({
      email: "mobile-login@example.com",
    });
    const { client } = await createTestClient({
      clientType: "public",
      redirectUris: ["noirly-pulse://oauth"],
    });

    const tokens = await mobileLoginWithPassword(
      {
        client_id: client.clientId,
        email: user.email,
        password,
        scope: "openid profile email offline_access",
      },
      { ipAddress: "127.0.0.1", userAgent: "vitest" },
    );

    expect(tokens.token_type).toBe("Bearer");
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.id_token).toBeTruthy();
    expect(tokens.refresh_token).toBeTruthy();
    expect(tokens.user.email).toBe(user.email);
    expect(await resolveAccessToken(tokens.access_token)).toBeTruthy();
  });

  it("registers then refreshes and logs out", async () => {
    const { client } = await createTestClient({
      clientType: "public",
      redirectUris: ["noirly-flow://oauth"],
    });

    // Registering creates the account but hands out no tokens until the
    // address is verified: anyone can register any email.
    await expect(
      mobileRegister(
        {
          client_id: client.clientId,
          email: "mobile-reg@example.com",
          password: "StrongPass1!",
          firstName: "Mobile",
          lastName: "User",
        },
        { ipAddress: "127.0.0.1", userAgent: "vitest" },
      ),
    ).rejects.toMatchObject({ code: "email_not_verified" });
    expect(await User.exists({ email: "mobile-reg@example.com", emailVerified: false })).toBeTruthy();

    // Signing in before verifying is refused too.
    await expect(
      mobileLoginWithPassword(
        { client_id: client.clientId, email: "mobile-reg@example.com", password: "StrongPass1!" },
        { ipAddress: "127.0.0.1", userAgent: "vitest" },
      ),
    ).rejects.toMatchObject({ code: "email_not_verified" });

    await User.updateOne(
      { email: "mobile-reg@example.com" },
      { $set: { emailVerified: true, status: "active" } },
    );
    const registered = await mobileLoginWithPassword(
      { client_id: client.clientId, email: "mobile-reg@example.com", password: "StrongPass1!" },
      { ipAddress: "127.0.0.1", userAgent: "vitest" },
    );

    expect(registered.user.email).toBe("mobile-reg@example.com");
    expect(registered.refresh_token).toBeTruthy();

    const refreshed = await mobileRefreshTokens({
      client_id: client.clientId,
      refresh_token: registered.refresh_token!,
    });
    expect(refreshed.access_token).not.toBe(registered.access_token);
    expect(refreshed.refresh_token).toBeTruthy();
    expect(refreshed.refresh_token).not.toBe(registered.refresh_token);

    await mobileLogout({
      client_id: client.clientId,
      refresh_token: refreshed.refresh_token,
    });

    await expect(
      mobileRefreshTokens({
        client_id: client.clientId,
        refresh_token: refreshed.refresh_token!,
      }),
    ).rejects.toBeInstanceOf(Error);
  });

  it("rejects invalid credentials", async () => {
    await createTestUser({ email: "mobile-bad@example.com" });
    const { client } = await createTestClient({
      clientType: "public",
      redirectUris: ["app://oauth"],
    });

    await expect(
      mobileLoginWithPassword(
        {
          client_id: client.clientId,
          email: "mobile-bad@example.com",
          password: "WrongPass1!",
        },
        { ipAddress: "127.0.0.1", userAgent: "vitest" },
      ),
    ).rejects.toBeInstanceOf(AppError);
  });
});
