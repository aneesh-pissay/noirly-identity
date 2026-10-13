import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { POST } from "@/app/api/mobile/browser-login/route";
import { createTestClient, createTestUser } from "./helpers";
import { createSession } from "@/lib/sessions/session-service";
import { getEnv } from "@/lib/config/env";
import { MobileBrowserLogin } from "@/models/MobileBrowserLogin";
import { Session } from "@/models/Session";

const jar = vi.hoisted(() => new Map<string, string>());
vi.mock("next/headers", () => ({ cookies: async () => ({ get: (key: string) => jar.has(key) ? { value: jar.get(key) } : undefined }) }));
beforeEach(() => jar.clear());

function post(body: Record<string, string>, csrf = true) {
  return POST(new NextRequest("http://localhost:3000/api/mobile/browser-login", { method: "POST", headers: { "content-type": "application/json", ...(csrf ? { "x-csrf-token": "test-csrf-value" } : {}) }, body: JSON.stringify(body) }));
}

async function setup() {
  const { client } = await createTestClient({ clientType: "public" });
  const { user } = await createTestUser();
  const session = await createSession({ userId: user._id, securityVerified: true });
  jar.set(getEnv().SESSION_COOKIE_NAME, session.token);
  jar.set(getEnv().CSRF_COOKIE_NAME, "test-csrf-value");
  const response = await post({ action: "start", client_id: client.clientId });
  expect(response.status).toBe(200);
  const start = await response.json();
  const request = new URL(start.url).searchParams.get("request")!;
  return { start, request, session, user };
}

describe("mobile browser approval", () => {
  it("requires CSRF and the displayed code, issues credentials once after approval", async () => {
    const { start, request, user } = await setup();
    expect(start.url).not.toContain(start.token);
    expect((await post({ action: "poll", token: start.token })).status).toBe(202);
    expect((await post({ action: "approve", request, code: start.displayCode }, false)).status).toBe(403);
    expect((await post({ action: "approve", request, code: "000000" })).status).toBe(400);
    expect((await post({ action: "approve", request, code: start.displayCode })).status).toBe(200);
    const completed = await post({ action: "poll", token: start.token });
    expect(completed.status).toBe(200);
    const result = await completed.json();
    expect(result.user.id).toBe(String(user._id));
    expect(result.access_token).toBeTruthy();
    expect((await post({ action: "poll", token: start.token })).status).toBe(410);
  });

  it("rejects expired requests", async () => {
    const { start } = await setup();
    await MobileBrowserLogin.updateMany({}, { expiresAt: new Date(0) });
    expect((await post({ action: "poll", token: start.token })).status).toBe(410);
  });

  it("does not mint tokens if the approving session was revoked", async () => {
    const { start, request, session } = await setup();
    expect((await post({ action: "approve", request, code: start.displayCode })).status).toBe(200);
    await Session.updateOne({ _id: session.session._id }, { revokedAt: new Date() });
    expect((await post({ action: "poll", token: start.token })).status).toBe(401);
  });
});
