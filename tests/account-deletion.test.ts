import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { importSPKI, jwtVerify } from "jose";
import { afterEach, describe, expect, it } from "vitest";
import {
  deleteAccountForAccessToken,
  deleteAccountForSession,
} from "@/lib/account/delete-account";
import {
  ACCOUNT_DELETED_EVENT,
  parseDeletionWebhooks,
  retryPendingDeletionNotices,
} from "@/lib/account/deletion-webhooks";
import { resetEnvCache } from "@/lib/config/env";
import { issueAccessToken, issueRefreshToken } from "@/lib/tokens/token-service";
import { AccessToken } from "@/models/AccessToken";
import { DeletedAccount } from "@/models/DeletedAccount";
import { LinkedAccount } from "@/models/LinkedAccount";
import { RefreshToken } from "@/models/RefreshToken";
import { Session } from "@/models/Session";
import { User } from "@/models/User";
import { createAuthedSession, createTestUser } from "./helpers";

/** A local webhook receiver that records request bodies (or fails on purpose). */
async function startReceiver(status = 200): Promise<{ url: string; bodies: string[]; server: Server }> {
  const bodies: string[] = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      bodies.push(body);
      res.statusCode = status;
      res.end("{}");
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return { url: `http://127.0.0.1:${port}/account-deleted`, bodies, server };
}

const servers: Server[] = [];

function useWebhooks(value: string | undefined) {
  if (value === undefined) delete process.env.ACCOUNT_DELETION_WEBHOOKS;
  else process.env.ACCOUNT_DELETION_WEBHOOKS = value;
  resetEnvCache();
}

afterEach(async () => {
  useWebhooks(undefined);
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

describe("account deletion", () => {
  it("refuses a wrong password and keeps the account", async () => {
    const { user } = await createTestUser();
    const { token } = await createAuthedSession(String(user._id));
    await expect(deleteAccountForSession(token, { password: "wrong-password" })).rejects.toMatchObject({
      code: "invalid_password",
    });
    expect(await User.countDocuments({ _id: user._id })).toBe(1);
  });

  it("deletes the account and every session, token and link with the right password", async () => {
    const { user, password } = await createTestUser();
    const { token, session } = await createAuthedSession(String(user._id));
    await issueAccessToken({ clientId: "app", userId: user._id, sessionId: session._id, scope: "openid" });
    await issueRefreshToken({ clientId: "app", userId: user._id, sessionId: session._id, scope: "openid" });
    await LinkedAccount.create({ userId: user._id, provider: "google", providerAccountId: "g-1" });

    await deleteAccountForSession(token, { password });

    expect(await User.countDocuments({ _id: user._id })).toBe(0);
    expect(await Session.countDocuments({ userId: user._id })).toBe(0);
    expect(await AccessToken.countDocuments({ userId: user._id })).toBe(0);
    expect(await RefreshToken.countDocuments({ userId: user._id })).toBe(0);
    expect(await LinkedAccount.countDocuments({ userId: user._id })).toBe(0);
  });

  it("asks Google-only accounts to type their email instead of a password", async () => {
    const { user } = await createTestUser({ email: "google@example.com" });
    await User.updateOne({ _id: user._id }, { $set: { passwordHash: null } });
    const { token } = await createAuthedSession(String(user._id));

    await expect(deleteAccountForSession(token, { confirmEmail: "other@example.com" })).rejects.toMatchObject({
      code: "confirmation_mismatch",
    });
    await deleteAccountForSession(token, { confirmEmail: "  Google@Example.com " });
    expect(await User.countDocuments({ _id: user._id })).toBe(0);
  });

  it("lets a mobile access token delete its own account", async () => {
    const { user, password } = await createTestUser();
    const { session } = await createAuthedSession(String(user._id));
    const { token } = await issueAccessToken({ clientId: "mobile", userId: user._id, sessionId: session._id, scope: "openid" });

    await expect(deleteAccountForAccessToken("not-a-token", { password })).rejects.toMatchObject({ code: "invalid_token" });
    await expect(deleteAccountForAccessToken(token, { password: "nope", verifyOnly: true })).rejects.toMatchObject({
      code: "invalid_password",
    });
    expect(await deleteAccountForAccessToken(token, { password, verifyOnly: true })).toMatchObject({ deleted: false });
    expect(await User.countDocuments({ _id: user._id })).toBe(1);
    await deleteAccountForAccessToken(token, { password });
    expect(await User.countDocuments({ _id: user._id })).toBe(0);
  });
});

describe("deletion notices", () => {
  it("parses clientId=url pairs and rejects http in production", () => {
    expect(parseDeletionWebhooks("flow=https://flow.example/api/hook, ledger=https://l.example/h", true)).toEqual([
      { clientId: "flow", url: "https://flow.example/api/hook" },
      { clientId: "ledger", url: "https://l.example/h" },
    ]);
    expect(() => parseDeletionWebhooks("flow=http://flow.example/hook", true)).toThrow(/https/);
    expect(() => parseDeletionWebhooks("just-a-url", false)).toThrow(/clientId=url/);
  });

  it("sends each app a signed account-deleted event for the user", async () => {
    const receiver = await startReceiver();
    servers.push(receiver.server);
    useWebhooks(`noirly-flow=${receiver.url}`);
    const { user, password } = await createTestUser();
    const { token } = await createAuthedSession(String(user._id));

    const result = await deleteAccountForSession(token, { password });

    expect(result).toEqual({ deleted: true, delivered: ["noirly-flow"], pending: [] });
    expect(receiver.bodies).toHaveLength(1);
    const key = await importSPKI(process.env.JWT_PUBLIC_KEY!.replace(/\\n/g, "\n"), "RS256");
    const { payload, protectedHeader } = await jwtVerify(receiver.bodies[0]!, key, {
      issuer: "http://localhost:3000",
      audience: "noirly-flow",
    });
    expect(protectedHeader.typ).toBe("secevent+jwt");
    expect(payload.sub).toBe(String(user._id));
    expect(payload.events).toEqual({ [ACCOUNT_DELETED_EVENT]: {} });
    expect(await DeletedAccount.countDocuments()).toBe(0);
  });

  it("keeps failed notices and delivers them on retry", async () => {
    const down = await startReceiver(503);
    servers.push(down.server);
    useWebhooks(`noirly-flow=${down.url}`);
    const { user, password } = await createTestUser();
    const { token } = await createAuthedSession(String(user._id));

    const result = await deleteAccountForSession(token, { password });
    expect(result.pending).toEqual(["noirly-flow"]);
    const tombstone = await DeletedAccount.findOne({ sub: String(user._id) }).lean();
    expect(tombstone?.pending[0]).toMatchObject({ clientId: "noirly-flow", attempts: 1, lastError: "HTTP 503" });

    const up = await startReceiver(200);
    servers.push(up.server);
    useWebhooks(`noirly-flow=${up.url}`);
    expect(await retryPendingDeletionNotices()).toBe(0);
    expect(up.bodies).toHaveLength(1);
    expect(await DeletedAccount.countDocuments()).toBe(0);
  });
});
