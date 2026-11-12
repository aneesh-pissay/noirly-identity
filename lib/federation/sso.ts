import { createHash, randomBytes } from "node:crypto";
import { SAML, ValidateInResponseTo, type CacheProvider, type Profile } from "@node-saml/node-saml";
import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from "jose";
import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { orgStream } from "@/lib/audit/chain";
import { recordEvent } from "@/lib/audit/event-log";
import { normalizeEmail, toPublicUser } from "@/lib/auth/user-mapper";
import { isBlockedUser } from "@/lib/auth/user-policy";
import { presetDefaults } from "@/lib/federation/presets";
import { spUrls } from "@/lib/federation/providers";
import { emitLifecycle } from "@/lib/webhooks/lifecycle";
import { noticeToUser, spaceName } from "@/lib/notifications/notices";
import { hmacSha256, safeEqualHex, safeEqualString } from "@/lib/security/crypto";
import { openSecret } from "@/lib/security/encryption";
import { createSession } from "@/lib/sessions/session-service";
import { FederatedIdentity, IdentityProvider, SamlCacheEntry, type IdentityProviderDocument } from "@/models/IdentityProvider";
import { OrganizationMembership } from "@/models/OrganizationMembership";
import { SpaceTeam } from "@/models/SpaceTeam";
import { User } from "@/models/User";
import { UserEmail } from "@/models/UserEmail";
import type { PublicUser } from "@/types";

/**
 * Signing in through an organization's own identity provider (OIDC or SAML).
 *
 * The browser carries a signed `noirly_sso` cookie from the start to the
 * finish (state, nonce, PKCE verifier, where to go back to), so an answer
 * can only finish the sign-in in the browser that asked for it. An IdP is
 * trusted for addresses at its organization's verified domains only, which
 * is what lets it sign into (and link) an existing account at such an address.
 */

export const SSO_COOKIE = "noirly_sso";
const STATE_TTL_MS = 10 * 60_000;

export type SsoState = { nonce: string; idpId: string; returnTo: string; exp: number; codeVerifier?: string; requestId?: string };

export function signSsoState(state: SsoState): string {
  const body = Buffer.from(JSON.stringify(state)).toString("base64url");
  return `${body}.${hmacSha256(`sso:${body}`)}`;
}

export function readSsoState(raw: string | null | undefined): SsoState | null {
  if (!raw) return null;
  const dot = raw.lastIndexOf(".");
  if (dot < 1 || !safeEqualHex(raw.slice(dot + 1), hmacSha256(`sso:${raw.slice(0, dot)}`))) return null;
  try {
    const state = JSON.parse(Buffer.from(raw.slice(0, dot), "base64url").toString("utf8")) as SsoState;
    return state.exp > Date.now() ? state : null;
  } catch {
    return null;
  }
}

/** node-saml's request-id and replay cache, in MongoDB (so it works across serverless instances). */
export const mongoSamlCache: CacheProvider = {
  async saveAsync(key, value) {
    await SamlCacheEntry.updateOne({ key }, { $set: { value, createdAt: new Date(), expiresAt: new Date(Date.now() + STATE_TTL_MS) } }, { upsert: true });
    return { value, createdAt: Date.now() };
  },
  async getAsync(key) {
    return (await SamlCacheEntry.findOne({ key }).lean())?.value ?? null;
  },
  async removeAsync(key) {
    if (!key) return null;
    return (await SamlCacheEntry.findOneAndDelete({ key }).lean())?.value ?? null;
  },
  async consumeAsync(key) {
    return (await SamlCacheEntry.findOneAndDelete({ key }).lean())?.value ?? null;
  },
  async saveIfAbsentAsync(key, value, expiresAtMs) {
    try {
      await SamlCacheEntry.create({ key, value, expiresAt: new Date(expiresAtMs) });
      return true;
    } catch {
      return false;
    }
  },
};

function samlFor(idp: IdentityProviderDocument): SAML {
  const urls = spUrls(String(idp._id));
  const now = Date.now();
  const certs = idp.saml!.certificates.filter((c) => c.notAfter.getTime() > now).map((c) => c.pem);
  if (!certs.length) throw new AppError("This identity provider's certificates have all expired; ask your admin to add the new one", 503, "idp_certificate_expired");
  return new SAML({
    callbackUrl: urls.acsUrl,
    entryPoint: idp.saml!.ssoUrl,
    issuer: urls.spEntityId,
    audience: urls.spEntityId,
    idpIssuer: idp.saml!.idpEntityId,
    idpCert: certs,
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: false,
    validateInResponseTo: ValidateInResponseTo.always,
    requestIdExpirationPeriodMs: STATE_TTL_MS,
    rejectReplayedAssertions: true,
    cacheProvider: mongoSamlCache,
    acceptedClockSkewMs: 60_000,
    identifierFormat: null,
    disableRequestedAuthnContext: true,
  });
}

/** SP metadata for the IdP admin to import. */
export function serviceProviderMetadata(idp: IdentityProviderDocument): string {
  return samlFor(idp).generateServiceProviderMetadata(null, null);
}

const pkceChallenge = (verifier: string) => createHash("sha256").update(verifier).digest("base64url");

/** Which provider: one by id, or the one for an address's domain. */
export async function findProvider(input: { idpId?: string | null; email?: string | null }): Promise<IdentityProviderDocument | null> {
  if (input.idpId) {
    if (!Types.ObjectId.isValid(input.idpId)) return null;
    return IdentityProvider.findOne({ _id: new Types.ObjectId(input.idpId), enabled: true }).lean<IdentityProviderDocument>();
  }
  const domain = input.email?.split("@")[1]?.toLowerCase();
  if (!domain) return null;
  return IdentityProvider.findOne({ domains: domain, enabled: true }).lean<IdentityProviderDocument>();
}

/** Where to send the browser, and the cookie to set. */
export async function startSso(idp: IdentityProviderDocument, returnTo: string, loginHint?: string | null): Promise<{ url: string; cookie: string }> {
  const nonce = randomBytes(24).toString("base64url");
  if (idp.protocol === "oidc") {
    const codeVerifier = randomBytes(32).toString("base64url");
    const url = new URL(idp.oidc!.authorizationEndpoint);
    url.search = new URLSearchParams({
      response_type: "code",
      client_id: idp.oidc!.clientId,
      redirect_uri: spUrls(String(idp._id)).oidcRedirectUri,
      scope: idp.oidc!.scopes.join(" "),
      state: nonce,
      nonce,
      code_challenge: pkceChallenge(codeVerifier),
      code_challenge_method: "S256",
      ...(loginHint ? { login_hint: loginHint } : {}),
    }).toString();
    return { url: url.toString(), cookie: signSsoState({ nonce, idpId: String(idp._id), returnTo, exp: Date.now() + STATE_TTL_MS, codeVerifier }) };
  }
  const url = await samlFor(idp).getAuthorizeUrlAsync(nonce, undefined, {});
  return { url, cookie: signSsoState({ nonce, idpId: String(idp._id), returnTo, exp: Date.now() + STATE_TTL_MS }) };
}

export type FederatedClaims = { subject: string; email: string; firstName: string; lastName: string; groups: string[] };

const jwksCache = new Map<string, { at: number; set: JSONWebKeySet }>();
async function jwksFor(uri: string, refresh = false): Promise<JSONWebKeySet> {
  const hit = jwksCache.get(uri);
  if (hit && !refresh && Date.now() - hit.at < 5 * 60_000) return hit.set;
  const res = await fetch(uri, { redirect: "error", signal: AbortSignal.timeout(8000), cache: "no-store" });
  if (!res.ok) throw new AppError("Couldn't reach the identity provider", 502, "idp_unreachable");
  const set = (await res.json()) as JSONWebKeySet;
  jwksCache.set(uri, { at: Date.now(), set });
  return set;
}
/** Tests: forget fetched keys. */
export function resetJwksCache() {
  jwksCache.clear();
}

const str = (v: unknown) => (typeof v === "string" ? v : Array.isArray(v) && typeof v[0] === "string" ? v[0] : "");
const list = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : typeof v === "string" ? [v] : []);

function claimsFrom(idp: IdentityProviderDocument, source: Record<string, unknown>, subject: string): FederatedClaims {
  const d = presetDefaults(idp.preset, idp.protocol);
  const m = idp.mapping ?? { email: "", firstName: "", lastName: "", groups: "" };
  const emailKey = m.email || d.email;
  const email = str(source[emailKey]) || (idp.protocol === "oidc" ? str(source.preferred_username) || str(source.upn) : str(source.mail) || str(source.email) || str(source.nameID));
  return {
    subject,
    email: normalizeEmail(email),
    firstName: str(source[m.firstName || d.firstName]).slice(0, 100),
    lastName: str(source[m.lastName || d.lastName]).slice(0, 100),
    groups: list(source[m.groups || d.groups]).slice(0, 500),
  };
}

/** OIDC: trades the code for tokens and checks the ID token. */
export async function finishOidc(state: SsoState, query: { code: string | null; state: string | null; error: string | null }): Promise<{ idp: IdentityProviderDocument; claims: FederatedClaims }> {
  if (query.error) throw new AppError("The sign-in was cancelled at your organization", 400, "sso_cancelled");
  if (!query.code || !query.state || !safeEqualString(query.state, state.nonce) || !state.codeVerifier) throw new AppError("That sign-in link has expired; try again", 400, "sso_state");
  const idp = await findProvider({ idpId: state.idpId });
  if (!idp || idp.protocol !== "oidc") throw new AppError("Single sign-on isn't set up here any more", 400, "sso_unavailable");
  const body = new URLSearchParams({ grant_type: "authorization_code", code: query.code, redirect_uri: spUrls(String(idp._id)).oidcRedirectUri, client_id: idp.oidc!.clientId, code_verifier: state.codeVerifier });
  if (idp.oidc!.clientSecretSealed) body.set("client_secret", openSecret(idp.oidc!.clientSecretSealed, `idp:${String(idp._id)}`));
  const res = await fetch(idp.oidc!.tokenEndpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" }, body, redirect: "error", signal: AbortSignal.timeout(10_000), cache: "no-store" });
  const tokens = (await res.json().catch(() => ({}))) as { id_token?: string };
  if (!res.ok || !tokens.id_token) throw new AppError("Your organization's sign-in didn't complete", 502, "sso_token");
  const verify = async (refresh: boolean) => jwtVerify(tokens.id_token!, createLocalJWKSet(await jwksFor(idp.oidc!.jwksUri, refresh)), { issuer: idp.oidc!.issuer, audience: idp.oidc!.clientId, clockTolerance: 60 });
  let payload: Record<string, unknown>;
  try {
    payload = (await verify(false)).payload;
  } catch {
    try {
      // The IdP may have rotated its keys.
      payload = (await verify(true)).payload;
    } catch {
      throw new AppError("Your organization's sign-in couldn't be verified", 401, "sso_invalid");
    }
  }
  if (payload.nonce !== state.nonce || typeof payload.sub !== "string") throw new AppError("Your organization's sign-in couldn't be verified", 401, "sso_invalid");
  // An address the IdP says it hasn't confirmed isn't used (Entra omits the claim; its addresses are the tenant's own).
  if (payload.email_verified === false) throw new AppError("Your organization hasn't confirmed your email address", 403, "sso_email_unverified");
  return { idp, claims: claimsFrom(idp, payload, payload.sub) };
}

/** SAML: a POSTed response is parked, so the GET that follows (with the browser's cookie) finishes it. */
export async function parkSamlResponse(samlResponse: string, relayState: string): Promise<string> {
  if (samlResponse.length > 200_000) throw new AppError("Response too large", 400, "invalid_request");
  const key = randomBytes(24).toString("base64url");
  await SamlCacheEntry.create({ key: `pending:${key}`, value: JSON.stringify({ samlResponse, relayState }), expiresAt: new Date(Date.now() + 2 * 60_000) });
  return key;
}

export async function finishSaml(state: SsoState, idpId: string, parked: string): Promise<{ idp: IdentityProviderDocument; claims: FederatedClaims }> {
  const entry = await SamlCacheEntry.findOneAndDelete({ key: `pending:${parked}` }).lean();
  if (!entry || entry.expiresAt.getTime() < Date.now()) throw new AppError("That sign-in has expired; try again", 400, "sso_state");
  const { samlResponse, relayState } = JSON.parse(entry.value) as { samlResponse: string; relayState: string };
  if (state.idpId !== idpId || !safeEqualString(relayState, state.nonce)) throw new AppError("That sign-in was started in another browser; try again", 400, "sso_state");
  const idp = await findProvider({ idpId });
  if (!idp || idp.protocol !== "saml") throw new AppError("Single sign-on isn't set up here any more", 400, "sso_unavailable");
  let profile: Profile | null;
  try {
    ({ profile } = await samlFor(idp).validatePostResponseAsync({ SAMLResponse: samlResponse, RelayState: relayState }));
  } catch (error) {
    if (error instanceof AppError) throw error;
    throw new AppError("Your organization's sign-in couldn't be verified", 401, "sso_invalid");
  }
  if (!profile?.nameID) throw new AppError("Your organization's sign-in couldn't be verified", 401, "sso_invalid");
  return { idp, claims: claimsFrom(idp, profile as Record<string, unknown>, profile.nameID) };
}

export type SsoMeta = { ipAddress?: string | null; userAgent?: string | null; place?: string | null; deviceId?: string | null };

/** Applies the IdP's groups: organization role (admin or member; never an owner's) and mapped teams. */
async function applyGroups(idp: IdentityProviderDocument, userId: Types.ObjectId, groups: string[]) {
  const m = idp.mapping;
  if (!m || (!m.roles.length && !m.teams.length)) return null;
  const has = new Set(groups);
  const changes: Record<string, unknown> = {};
  if (m.roles.length) {
    const role = m.roles.some((r) => r.role === "admin" && has.has(r.group)) ? "admin" : "member";
    const updated = await OrganizationMembership.updateOne({ organizationId: idp.organizationId, userId, role: { $in: ["admin", "member"], $ne: role } }, { $set: { role } });
    if (updated.modifiedCount) changes.role = role;
  }
  for (const rule of m.teams) {
    const inGroup = has.has(rule.group);
    const r = await SpaceTeam.updateOne({ _id: rule.teamId, organizationId: idp.organizationId }, inGroup ? { $addToSet: { memberIds: userId } } : { $pull: { memberIds: userId } });
    if (r.modifiedCount) changes[`team:${String(rule.teamId)}`] = inGroup ? "added" : "removed";
  }
  return Object.keys(changes).length ? changes : null;
}

/** Finds, links or (just in time) creates the account, keeps its membership in step, and signs in. */
export async function completeFederatedSignIn(idp: IdentityProviderDocument, claims: FederatedClaims, meta: SsoMeta): Promise<{ user: PublicUser; sessionToken: string; created: boolean }> {
  const domain = claims.email.split("@")[1] ?? "";
  if (!claims.email.includes("@") || !idp.domains.includes(domain)) {
    throw new AppError("Your organization's sign-in is for its own addresses only; this one isn't", 403, "sso_domain_mismatch");
  }
  let created = false;
  const link = await FederatedIdentity.findOne({ idpId: idp._id, subject: claims.subject }).lean();
  let user = link ? await User.findById(link.userId) : null;
  if (!user) {
    user = await User.findOne({ email: claims.email });
    if (!user) {
      const additional = await UserEmail.findOne({ email: claims.email, verifiedAt: { $ne: null } }).lean();
      if (additional) user = await User.findById(additional.userId);
    }
    if (user) {
      // The organization owns the domain and its IdP proves the address: whatever an earlier,
      // unconfirmed registrant set up for it goes (as with Google, lib/auth/provider-login.ts).
      if (!user.emailVerified) {
        const { discardUnverifiedRegistration } = await import("@/lib/auth/provider-login");
        await discardUnverifiedRegistration(user);
      }
    } else if (idp.jit) {
      // Names the IdP doesn't send can be filled in on the account page.
      const firstName = claims.firstName || claims.email.split("@")[0]!.slice(0, 100);
      const lastName = claims.lastName || "User";
      user = await User.create({ email: claims.email, passwordHash: null, firstName, lastName, displayName: `${firstName} ${lastName}`.trim(), emailVerified: true, status: "active", roles: ["user"] });
      created = true;
      await recordEvent({ action: "account.registered", subjectId: user._id, request: meta, data: { method: "sso", idpId: String(idp._id), organizationId: String(idp.organizationId) } });
    } else {
      throw new AppError("You don't have an account here yet; ask your organization's admin to add you", 403, "sso_no_account");
    }
    await FederatedIdentity.updateOne({ idpId: idp._id, subject: claims.subject }, { $set: { userId: user._id } }, { upsert: true });
    if (!created) await recordEvent({ action: "account.identity_linked", subjectId: user._id, request: meta, data: { provider: "sso", idpId: String(idp._id) } });
  }
  if (isBlockedUser(user)) throw new AppError("Unable to sign in", 401, "invalid_credentials");

  if (claims.email === user.email && !user.emailVerified) user.emailVerified = true;
  if (user.status === "pending_verification") user.status = "active";
  if (claims.firstName && user.firstName !== claims.firstName) user.firstName = claims.firstName;
  if (claims.lastName && user.lastName !== claims.lastName) user.lastName = claims.lastName;
  user.lastLoginAt = new Date();
  await user.save();

  // Membership of the organization comes with its sign-in.
  const joined = await OrganizationMembership.updateOne({ organizationId: idp.organizationId, userId: user._id }, { $setOnInsert: { role: "member" } }, { upsert: true });
  const spaceId = String(idp.organizationId);
  if (created) {
    await emitLifecycle("user.created", { userId: String(user._id), organizationId: spaceId, data: { via: "sso" } });
    const name = await spaceName(spaceId);
    await noticeToUser(user._id, {
      kind: "account-created-by-org",
      subject: `Your Noirly account, through ${name}`,
      paragraphs: [
        `You signed in to Noirly for the first time with ${name}'s sign-in (${idp.name}), so a Noirly account was made for ${user.email} and you joined ${name}'s space.`,
        `You sign in the same way from now on: type your address on any Noirly sign-in page. ${name} manages this account: it can change your name and role, and turn the account off if you leave.`,
      ],
      action: { label: "See your account", path: "/account" },
    });
  }
  if (joined.upsertedCount) {
    await recordEvent({ action: "sso.user_provisioned", stream: orgStream(spaceId), actorId: null, subjectId: user._id, data: { organizationId: spaceId, idpId: String(idp._id), accountCreated: created } });
    await emitLifecycle("membership.changed", { userId: String(user._id), organizationId: spaceId, data: { change: "joined", role: "member", via: "sso" } });
  }
  const mapped = await applyGroups(idp, user._id, claims.groups);
  if (mapped) {
    await recordEvent({ action: "sso.groups_mapped", stream: orgStream(spaceId), actorId: null, subjectId: user._id, data: { organizationId: spaceId, idpId: String(idp._id), changes: mapped } });
    await emitLifecycle("membership.changed", { userId: String(user._id), organizationId: spaceId, data: { change: "groups_mapped", ...mapped } });
  }

  await Promise.all([
    FederatedIdentity.updateOne({ idpId: idp._id, subject: claims.subject }, { $set: { lastSignInAt: new Date() } }),
    IdentityProvider.updateOne({ _id: idp._id }, { $set: { lastUsedAt: new Date() } }),
  ]);
  const { token } = await createSession({ userId: user._id, ipAddress: meta.ipAddress, userAgent: meta.userAgent, place: meta.place, deviceId: meta.deviceId, methods: ["sso"] });
  await recordEvent({ action: "auth.signed_in", subjectId: user._id, request: meta, data: { methods: ["sso"], idpId: String(idp._id), organizationId: spaceId } });
  return { user: toPublicUser(user), sessionToken: token, created };
}
