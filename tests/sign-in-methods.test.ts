import { describe, expect, it } from "vitest";
import { assertKeepsAWayIn, linkGoogle, listSignInMethods, removePassword, setPassword, unlinkProvider } from "@/lib/account/identities";
import { loginUser } from "@/lib/auth/auth-service";
import { validateSession } from "@/lib/sessions/session-service";
import { methodCount } from "@/lib/account/sign-in-methods";
import { listEvents } from "@/lib/audit/event-log";
import { loginWithGoogleProfile, type GoogleProfile } from "@/lib/auth/google";
import { readOAuthState, signOAuthState } from "@/lib/auth/oauth-state";
import { LinkedAccount } from "@/models/LinkedAccount";
import { Passkey } from "@/models/SecurityCredential";
import { User } from "@/models/User";
import { createAuthedSession, createTestUser } from "./helpers";

const google = (sub: string, email = "someone@gmail.com"): GoogleProfile => ({ sub, email, emailVerified: true, firstName: "Test", lastName: "User", displayName: "Test User", avatarUrl: null });

async function googleOnlyUser(email = "only-google@example.com") {
  const user = await User.create({ email, passwordHash: null, firstName: "G", lastName: "O", displayName: "G O", emailVerified: true, status: "active" });
  await LinkedAccount.create({ userId: user._id, provider: "google", providerAccountId: `sub-${email}`, email });
  return user;
}

describe("ways to sign in", () => {
  it("counts each kind once", () => {
    expect(methodCount({ password: true, passkeys: 3 })).toBe(2);
    expect(methodCount({ password: false, passkeys: 0 })).toBe(0);
  });

  it("links Google from settings, once, and only to one account", async () => {
    const { user } = await createTestUser();
    const other = await createTestUser({ email: "other@example.com" });
    const id = String(user._id);
    await linkGoogle(id, google("g-1", "work@gmail.com"), { ipAddress: "203.0.113.7" });
    await linkGoogle(id, google("g-1", "work@gmail.com"));
    expect(await LinkedAccount.countDocuments({ userId: user._id })).toBe(1);
    await expect(linkGoogle(id, google("g-2"))).rejects.toMatchObject({ code: "already_linked" });
    await expect(linkGoogle(String(other.user._id), google("g-1"))).rejects.toMatchObject({ code: "linked_elsewhere" });

    const methods = await listSignInMethods(id);
    expect(methods).toMatchObject({ password: true, passkeys: 0, providers: [{ provider: "google", linked: { email: "work@gmail.com" } }, { provider: "apple", linked: null }, { provider: "microsoft", linked: null }, { provider: "github", linked: null }] });
    // Linked, but never a way to sign in.
    await expect(loginWithGoogleProfile(google("g-1", "work@gmail.com"), {})).rejects.toMatchObject({ code: "provider_sign_in_off" });
    const [event] = (await listEvents({ action: "account.identity_linked" })).events;
    expect(event).toMatchObject({ subjectId: id, data: { provider: "google", email: "work@gmail.com", fromSettings: true } });
  });

  it("unlinks Google whenever asked: it was never a way in", async () => {
    const { user } = await createTestUser();
    await linkGoogle(String(user._id), google("g-3"));
    const after = await unlinkProvider(String(user._id), "google");
    expect(after.providers[0]!.linked).toBeNull();
    expect((await listEvents({ action: "account.identity_unlinked" })).events).toHaveLength(1);

    const only = await googleOnlyUser();
    await unlinkProvider(String(only._id), "google");
    expect(await LinkedAccount.countDocuments({ userId: only._id })).toBe(0);
  });

  it("keeps the last passkey on an account with nothing else", async () => {
    const only = await googleOnlyUser("passkey-only@example.com");
    await Passkey.create({ userId: only._id, credentialId: "cred-a", publicKey: "key", counter: 0 });
    await Passkey.create({ userId: only._id, credentialId: "cred-b", publicKey: "key", counter: 0 });
    await LinkedAccount.deleteMany({ userId: only._id });
    // Two passkeys: one can go.
    await expect(assertKeepsAWayIn(String(only._id), { passkeys: 1 })).resolves.toBeUndefined();
    await Passkey.deleteOne({ credentialId: "cred-a" });
    await expect(assertKeepsAWayIn(String(only._id), { passkeys: 1 })).rejects.toMatchObject({ code: "last_sign_in_method" });
  });

  it("carries the linking session through Google in the signed state", () => {
    const signed = signOAuthState({ state: "s", codeVerifier: "v", returnTo: "/account", nonce: "n", exp: Date.now() + 60_000, linkSessionId: "abc123" });
    expect(readOAuthState(signed)?.linkSessionId).toBe("abc123");
    // Someone else's session swapped in, under the original signature.
    const forged = `${Buffer.from(JSON.stringify({ state: "s", codeVerifier: "v", returnTo: "/account", nonce: "n", exp: Date.now() + 60_000, linkSessionId: "someone-else" })).toString("base64url")}.${signed.split(".")[1]}`;
    expect(readOAuthState(forged)).toBeNull();
  });
});

describe("password settings", () => {
  it("adds a password to an account without one, and refuses one that has it", async () => {
    const only = await googleOnlyUser("adds-password@example.com");
    const after = await setPassword(String(only._id), "BrandNew1!pass");
    expect(after.password).toBe(true);
    expect(await loginUser({ email: "adds-password@example.com", password: "BrandNew1!pass" }, {})).toMatchObject({ user: { email: "adds-password@example.com" } });
    await expect(setPassword(String(only._id), "Another1!pass")).rejects.toMatchObject({ code: "password_exists" });
  });

  it("removes a password when there's a passkey too, signing out other sessions", async () => {
    const { user } = await createTestUser();
    const id = String(user._id);
    const kept = await createAuthedSession(id);
    const other = await createAuthedSession(id);
    await expect(removePassword(id, String(kept.session._id))).rejects.toMatchObject({ code: "last_sign_in_method" });
    // A linked Google account isn't a way in; a passkey is.
    await linkGoogle(id, google("g-pw"));
    await expect(removePassword(id, String(kept.session._id))).rejects.toMatchObject({ code: "last_sign_in_method" });
    await Passkey.create({ userId: user._id, credentialId: "cred-pw", publicKey: "key", counter: 0 });
    const after = await removePassword(id, String(kept.session._id));
    expect(after.password).toBe(false);
    expect(await validateSession(kept.token)).not.toBeNull();
    expect(await validateSession(other.token)).toBeNull();
    const [event] = (await listEvents({ action: "password.removed" })).events;
    expect(event!.data).toEqual({ otherSessionsSignedOut: true });
  });
});
