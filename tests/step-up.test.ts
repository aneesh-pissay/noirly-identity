import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { decodeJwt } from "jose";
import { generate } from "otplib";
import { GET as authorize } from "@/app/api/oauth/authorize/route";
import { GET as stepUp } from "@/app/api/auth/step-up/route";
import { POST as mfa } from "@/app/api/auth/mfa/route";
import { ACR_MFA, ACR_SINGLE, acrFor, amrFor, satisfiesAcr } from "@/lib/auth/acr";
import { getEnv } from "@/lib/config/env";
import { createAuthorizationCode } from "@/lib/oauth/authorize";
import { exchangeAuthorizationCode } from "@/lib/oauth/token";
import { buildDiscoveryDocument } from "@/lib/oidc/discovery";
import { generateSecureToken } from "@/lib/security/crypto";
import { beginTotp, confirmTotp } from "@/lib/security/mfa";
import { createSession } from "@/lib/sessions/session-service";
import { Session } from "@/models/Session";
import { createTestClient, createTestUser, pkceChallenge } from "./helpers";

const jar = vi.hoisted(() => new Map<string, string>());
vi.mock("next/headers", () => ({ cookies: async () => ({ get: (key: string) => (jar.has(key) ? { value: jar.get(key) } : undefined) }) }));
beforeEach(() => jar.clear());

describe("acr and amr", () => {
  it("describe how a session was signed in", () => {
    expect(amrFor(["password"])).toEqual(["pwd"]);
    expect(acrFor(["password"])).toBe(ACR_SINGLE);
    expect(amrFor(["password", "totp"])).toEqual(["pwd", "otp", "mfa"]);
    expect(acrFor(["google", "passkey"])).toBe(ACR_MFA);
    // A passkey alone checked a PIN or fingerprint: two factors in one.
    expect(acrFor(["passkey"])).toBe(ACR_MFA);
    expect(amrFor(["passkey"])).toEqual(["hwk", "user", "mfa"]);
  });

  it("match what an app asked for, ignoring levels Identity doesn't know", () => {
    expect(satisfiesAcr(ACR_SINGLE, [ACR_MFA])).toBe(false);
    expect(satisfiesAcr(ACR_MFA, [ACR_MFA])).toBe(true);
    expect(satisfiesAcr(ACR_SINGLE, [ACR_SINGLE, ACR_MFA])).toBe(true);
    expect(satisfiesAcr(ACR_SINGLE, ["urn:someone-else:gold"])).toBe(true);
    expect(buildDiscoveryDocument()).toMatchObject({ acr_values_supported: [ACR_SINGLE, ACR_MFA], claims_supported: expect.arrayContaining(["amr", "acr"]) });
  });
});

async function setup(methods: Array<"password" | "totp">, opts: { totp?: boolean; ageMs?: number } = {}) {
  const { user } = await createTestUser();
  const { client, clientSecret } = await createTestClient();
  let totpSecret: string | null = null;
  if (opts.totp) {
    const enrollment = await beginTotp(String(user._id), user.email);
    await confirmTotp(String(user._id), await generate({ secret: enrollment.secret }));
    totpSecret = enrollment.secret;
  }
  const { token, session } = await createSession({ userId: user._id, methods });
  if (opts.ageMs) await Session.updateOne({ _id: session._id }, { $set: { createdAt: new Date(Date.now() - opts.ageMs) } });
  jar.set(getEnv().SESSION_COOKIE_NAME, token);
  jar.set(getEnv().CSRF_COOKIE_NAME, "csrf");
  return { user, client, clientSecret, sessionToken: token, session, totpSecret };
}

function authorizeUrl(clientId: string, redirectUri: string, extra: Record<string, string> = {}) {
  const url = new URL("http://localhost:3000/api/oauth/authorize");
  const verifier = generateSecureToken(32);
  for (const [k, v] of Object.entries({ client_id: clientId, redirect_uri: redirectUri, response_type: "code", scope: "openid", state: "st", code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", ...extra })) url.searchParams.set(k, v);
  return url;
}

const where = (response: Response) => new URL(response.headers.get("location")!);

describe("step-up on authorize", () => {
  it("sends prompt=login to a fresh sign-in, and comes back needing one newer than the request", async () => {
    const { client } = await setup(["password"]);
    const response = await authorize(new NextRequest(authorizeUrl(client.clientId, client.redirectUris[0]!, { prompt: "login" })));
    const login = where(response);
    expect(login.pathname).toBe("/login");
    expect(login.searchParams.get("reauth")).toBe("1");
    const back = new URL(login.searchParams.get("return_to")!);
    expect(back.searchParams.get("prompt")).toBeNull();
    // Coming back with the same old session isn't enough.
    const again = await authorize(new NextRequest(back));
    expect(where(again).pathname).toBe("/login");
  });

  it("asks for a fresh sign-in past max_age, and lets a recent one through", async () => {
    const old = await setup(["password"], { ageMs: 10 * 60_000 });
    expect(where(await authorize(new NextRequest(authorizeUrl(old.client.clientId, old.client.redirectUris[0]!, { max_age: "300" })))).pathname).toBe("/login");
    expect(where(await authorize(new NextRequest(authorizeUrl(old.client.clientId, old.client.redirectUris[0]!, { max_age: "3600" })))).searchParams.get("code")).toBeTruthy();
    const none = where(await authorize(new NextRequest(authorizeUrl(old.client.clientId, old.client.redirectUris[0]!, { max_age: "300", prompt: "none" }))));
    expect(none.searchParams.get("error")).toBe("login_required");
  });

  it("steps up to a second factor for acr_values, in place, then issues tokens saying so", async () => {
    const { user, client, clientSecret, sessionToken, session, totpSecret } = await setup(["password"], { totp: true });
    const wanting = authorizeUrl(client.clientId, client.redirectUris[0]!, { acr_values: ACR_MFA });
    const first = where(await authorize(new NextRequest(wanting)));
    expect(first.pathname).toBe("/api/auth/step-up");

    const toMfa = await stepUp(new NextRequest(first));
    expect(where(toMfa).pathname).toBe("/mfa");
    const challenge = toMfa.headers.get("set-cookie")!.match(/noirly_mfa_challenge=([^;]+)/)![1]!;
    const verified = await mfa(new NextRequest("http://localhost:3000/api/auth/mfa", {
      method: "POST",
      headers: { "content-type": "application/json", "x-csrf-token": "csrf", cookie: `noirly_mfa_challenge=${challenge}` },
      // The next window's code: the current one was spent setting the app up.
      body: JSON.stringify({ action: "code", code: await generate({ secret: totpSecret!, epoch: Math.floor(Date.now() / 1000) + 30 }) }),
    }));
    expect(verified.status).toBe(200);
    // Same session, now strong enough: no new session cookie.
    expect(verified.headers.get("set-cookie") ?? "").not.toContain(getEnv().SESSION_COOKIE_NAME);
    expect((await Session.findById(session._id).lean())!.methods).toEqual(["password", "totp"]);

    const done = where(await authorize(new NextRequest(wanting)));
    expect(done.searchParams.get("code")).toBeTruthy();
    const verifier = generateSecureToken(32);
    const { code } = await createAuthorizationCode({ sessionToken, clientId: client.clientId, redirectUri: client.redirectUris[0]!, scope: "openid", codeChallenge: pkceChallenge(verifier), codeChallengeMethod: "S256" });
    const tokens = await exchangeAuthorizationCode({ code, redirectUri: client.redirectUris[0]!, clientId: client.clientId, clientSecret, codeVerifier: verifier, authorizationHeader: null });
    const claims = decodeJwt(tokens.id_token);
    expect(claims).toMatchObject({ sub: String(user._id), acr: ACR_MFA, amr: ["pwd", "otp", "mfa"] });
    expect(typeof claims.auth_time).toBe("number");
  });

  it("tells the app when there's no second step to ask for", async () => {
    const { client } = await setup(["password"]);
    const answer = where(await authorize(new NextRequest(authorizeUrl(client.clientId, client.redirectUris[0]!, { acr_values: ACR_MFA }))));
    expect(answer.searchParams.get("error")).toBe("unmet_authentication_requirements");
  });
});
