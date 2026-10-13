import { afterEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { POST as webLogin } from "@/app/api/auth/login/route";
import { POST as mobileLogin } from "@/app/api/mobile/login/route";
import { readFormBody } from "@/lib/api/request";
import { User } from "@/models/User";
import { OAuthClient } from "@/models/OAuthClient";
import { Session } from "@/models/Session";
import { createTestClient, createTestUser } from "./helpers";
import {
  mobileRefreshSchema,
  registerSchema,
  resetPasswordSchema,
  updateProfileSchema,
} from "@/lib/validation/schemas";

// Supply Next's request cookie context; keep the real CSRF comparison.
vi.mock("next/headers", () => ({
  cookies: async () => ({ get: () => ({ value: "nosql-audit-csrf" }) }),
}));

afterEach(() => vi.restoreAllMocks());

const payloads = [
  { $ne: null },
  { $gt: "" },
  { $regex: ".*" },
  { $in: ["victim@example.com"] },
  ["victim@example.com"],
  null,
];

function jsonRequest(body: unknown) {
  return new NextRequest("http://localhost:3000/api/auth/login", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-csrf-token": "nosql-audit-csrf",
    },
    body: JSON.stringify(body),
  });
}

describe("NoSQL injection at login HTTP boundaries", () => {
  for (const [name, handler, fields] of [
    ["web", webLogin, ["email", "password"]],
    ["mobile", mobileLogin, ["email", "password", "client_id"]],
  ] as const) {
    for (const field of fields) {
      it.each(payloads)(`${name} rejects an operator/array/null in ${field}: %j`, async (value) => {
        const userLookup = vi.spyOn(User, "findOne");
        const clientLookup = vi.spyOn(OAuthClient, "findOne");
        const response = await handler(jsonRequest({
          email: "victim@example.com",
          password: "StrongPass1!",
          client_id: "noirly-flow-mobile",
          [field]: value,
        }));
        expect(response.status).toBe(400);
        expect(await response.json()).toMatchObject({ error: "validation_error" });
        expect(userLookup).not.toHaveBeenCalled();
        expect(clientLookup).not.toHaveBeenCalled();
        expect(await Session.countDocuments()).toBe(0);
      });
    }
  }

  it("still accepts legitimate web and mobile credentials", async () => {
    const { user, password } = await createTestUser();
    const { client } = await createTestClient({ clientType: "public" });
    for (const handler of [webLogin, mobileLogin]) {
      const response = await handler(jsonRequest({
        email: user.email, password, client_id: client.clientId,
      }));
      expect(response.status).toBe(200);
    }
  });

  it("does not execute a password containing MongoDB syntax", async () => {
    const { user } = await createTestUser();
    const response = await webLogin(jsonRequest({
      email: user.email,
      password: '{"$ne":null}',
      $where: "return true",
    }));
    expect(response.status).toBe(401);
    expect(await Session.countDocuments()).toBe(0);
  });
});

describe("other Identity request boundaries", () => {
  it.each(payloads)("rejects operators and arrays in registration, refresh, reset and profile fields: %j", (value) => {
    expect(registerSchema.safeParse({
      email: value, password: "StrongPass1!", firstName: "A", lastName: "B",
    }).success).toBe(false);
    expect(mobileRefreshSchema.safeParse({
      client_id: value, refresh_token: "valid-token",
    }).success).toBe(false);
    expect(mobileRefreshSchema.safeParse({
      client_id: "noirly-flow-mobile", refresh_token: value,
    }).success).toBe(false);
    expect(resetPasswordSchema.safeParse({
      token: value, newPassword: "StrongPass1!",
    }).success).toBe(false);
    expect(updateProfileSchema.safeParse({ firstName: value }).success).toBe(false);
  });

  it("strips unrecognized MongoDB operators and privilege fields from profiles", () => {
    expect(updateProfileSchema.parse({
      firstName: "Alice", $set: { roles: ["admin"] }, roles: ["admin"],
      "roles.0": "admin", $where: "return true",
    })).toEqual({ firstName: "Alice" });
  });

  it("OAuth JSON/form parsing never promotes client_id operators to a query object", async () => {
    const form = await readFormBody(jsonRequest({ client_id: { $ne: null } }));
    expect(form.get("client_id")).toBe("[object Object]");
    const bracketed = new URLSearchParams("client_id%5B%24ne%5D=x&token=t");
    expect(bracketed.get("client_id")).toBeNull();
  });
});
