import { X509Certificate } from "node:crypto";
import { DOMParser } from "@xmldom/xmldom";
import { Types } from "mongoose";
import { AppError } from "@/lib/api/errors";
import { orgStream } from "@/lib/audit/chain";
import { recordEvent } from "@/lib/audit/event-log";
import { getEnv } from "@/lib/config/env";
import { presetIssuer, presetScopes } from "@/lib/federation/presets";
import { sealSecret } from "@/lib/security/encryption";
import { actorLabel, noticeToSpaceOwners, spaceName } from "@/lib/notifications/notices";
import { requireDomainOwner } from "@/lib/spaces/domains";
import { roleIn } from "@/lib/spaces/space-service";
import { IdentityProvider, type FederationPreset, type FederationProtocol, type IdentityProviderDocument, type SamlCertificate } from "@/models/IdentityProvider";
import { SpaceDomain } from "@/models/SpaceDomain";
import { SpaceTeam } from "@/models/SpaceTeam";

/**
 * An organization's identity providers (several allowed, each for some of
 * its verified domains). Managed by owners, or admins given the domains area:
 * routing a domain's sign-ins is as powerful as owning the domain.
 */

const MAX_PROVIDERS = 10;

export type ProviderInput = {
  name: string;
  protocol: FederationProtocol;
  preset?: FederationPreset;
  enabled?: boolean;
  domains: string[];
  jit?: boolean;
  oidc?: { issuer?: string; tenant?: string; oktaDomain?: string; clientId: string; clientSecret?: string | null };
  saml?: { idpEntityId?: string; ssoUrl?: string; certificates?: string[]; metadataXml?: string; metadataUrl?: string | null };
  mapping?: { email?: string; firstName?: string; lastName?: string; groups?: string; roles?: Array<{ group: string; role: "admin" | "member" }>; teams?: Array<{ group: string; teamId: string }> };
};

export type ProviderView = {
  id: string;
  name: string;
  protocol: FederationProtocol;
  preset: FederationPreset;
  enabled: boolean;
  domains: string[];
  jit: boolean;
  oidc: { issuer: string; clientId: string; hasSecret: boolean; scopes: string[]; redirectUri: string } | null;
  saml: { idpEntityId: string; ssoUrl: string; metadataUrl: string | null; certificates: Array<{ fingerprint: string; notAfter: string }>; spEntityId: string; acsUrl: string; spMetadataUrl: string } | null;
  mapping: { email: string; firstName: string; lastName: string; groups: string; roles: Array<{ group: string; role: string }>; teams: Array<{ group: string; teamId: string }> };
  lastUsedAt: string | null;
};

export function spUrls(idpId: string) {
  const base = getEnv().APP_URL.replace(/\/+$/, "");
  return {
    spEntityId: `${base}/api/sso/saml/${idpId}/metadata`,
    acsUrl: `${base}/api/sso/saml/${idpId}/acs`,
    spMetadataUrl: `${base}/api/sso/saml/${idpId}/metadata`,
    oidcRedirectUri: `${base}/api/sso/oidc/callback`,
  };
}

export function providerView(p: IdentityProviderDocument): ProviderView {
  const urls = spUrls(String(p._id));
  return {
    id: String(p._id),
    name: p.name,
    protocol: p.protocol,
    preset: p.preset,
    enabled: p.enabled,
    domains: p.domains,
    jit: p.jit,
    oidc: p.oidc ? { issuer: p.oidc.issuer, clientId: p.oidc.clientId, hasSecret: Boolean(p.oidc.clientSecretSealed), scopes: p.oidc.scopes, redirectUri: urls.oidcRedirectUri } : null,
    saml: p.saml
      ? { idpEntityId: p.saml.idpEntityId, ssoUrl: p.saml.ssoUrl, metadataUrl: p.saml.metadataUrl, certificates: p.saml.certificates.map((c) => ({ fingerprint: c.fingerprint, notAfter: c.notAfter.toISOString() })), spEntityId: urls.spEntityId, acsUrl: urls.acsUrl, spMetadataUrl: urls.spMetadataUrl }
      : null,
    mapping: {
      email: p.mapping?.email ?? "",
      firstName: p.mapping?.firstName ?? "",
      lastName: p.mapping?.lastName ?? "",
      groups: p.mapping?.groups ?? "",
      roles: (p.mapping?.roles ?? []).map((r) => ({ group: r.group, role: r.role })),
      teams: (p.mapping?.teams ?? []).map((t) => ({ group: t.group, teamId: String(t.teamId) })),
    },
    lastUsedAt: p.lastUsedAt ? p.lastUsedAt.toISOString() : null,
  };
}

function httpsUrl(value: string, label: string) {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new AppError(`${label} isn't a URL`, 400, "invalid_request");
  }
  const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol !== "https:" && !(local && getEnv().NODE_ENV !== "production")) throw new AppError(`${label} must use https`, 400, "invalid_request");
  return url.toString();
}

/** A PEM (or bare base64) certificate, checked and summarized. */
export function parseCertificate(input: string): SamlCertificate {
  const body = input.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/=]{100,}$/.test(body)) throw new AppError("That isn't a certificate", 400, "invalid_certificate");
  const pem = `-----BEGIN CERTIFICATE-----\n${body.match(/.{1,64}/g)!.join("\n")}\n-----END CERTIFICATE-----\n`;
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(pem);
  } catch {
    throw new AppError("That isn't a certificate", 400, "invalid_certificate");
  }
  return { pem, fingerprint: cert.fingerprint256, notAfter: new Date(cert.validTo), alertedAt: null };
}

/** The entity id, sign-in URL (HTTP-Redirect) and signing certificates from IdP metadata. */
export function parseIdpMetadata(xml: string): { idpEntityId: string; ssoUrl: string; certificates: string[] } {
  if (xml.length > 500_000) throw new AppError("Metadata too large", 400, "invalid_metadata");
  const doc = new DOMParser().parseFromString(xml, "text/xml");
  const ns = "urn:oasis:names:tc:SAML:2.0:metadata";
  const entity = doc.getElementsByTagNameNS(ns, "EntityDescriptor")[0];
  const idp = doc.getElementsByTagNameNS(ns, "IDPSSODescriptor")[0];
  if (!entity || !idp) throw new AppError("That isn't SAML IdP metadata", 400, "invalid_metadata");
  const sso = Array.from(idp.getElementsByTagNameNS(ns, "SingleSignOnService")).find((e) => e.getAttribute("Binding") === "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
  const certificates: string[] = [];
  for (const key of Array.from(idp.getElementsByTagNameNS(ns, "KeyDescriptor"))) {
    const use = key.getAttribute("use");
    if (use && use !== "signing") continue;
    for (const c of Array.from(key.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "X509Certificate"))) {
      if (c.textContent) certificates.push(c.textContent.trim());
    }
  }
  const idpEntityId = entity.getAttribute("entityID");
  if (!idpEntityId || !sso?.getAttribute("Location") || !certificates.length) throw new AppError("The metadata lacks an entity ID, a redirect sign-in URL or a signing certificate", 400, "invalid_metadata");
  return { idpEntityId, ssoUrl: sso.getAttribute("Location")!, certificates };
}

type Discovery = { issuer: string; authorization_endpoint: string; token_endpoint: string; jwks_uri: string };

async function discover(issuer: string): Promise<Discovery> {
  let doc: Partial<Discovery>;
  try {
    const res = await fetch(`${issuer}/.well-known/openid-configuration`, { redirect: "error", signal: AbortSignal.timeout(8000), cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    doc = (await res.json()) as Partial<Discovery>;
  } catch {
    throw new AppError("Couldn't read the provider's OpenID configuration; check the issuer", 400, "discovery_failed");
  }
  if (doc.issuer?.replace(/\/+$/, "") !== issuer || !doc.authorization_endpoint || !doc.token_endpoint || !doc.jwks_uri) {
    throw new AppError("The provider's OpenID configuration doesn't match its issuer", 400, "discovery_failed");
  }
  return { issuer: doc.issuer!.replace(/\/+$/, ""), authorization_endpoint: httpsUrl(doc.authorization_endpoint, "Authorization endpoint"), token_endpoint: httpsUrl(doc.token_endpoint, "Token endpoint"), jwks_uri: httpsUrl(doc.jwks_uri, "JWKS URI") };
}

async function checkDomains(spaceId: Types.ObjectId, domains: string[]) {
  const wanted = [...new Set(domains.map((d) => d.trim().toLowerCase()))];
  const verified = await SpaceDomain.find({ organizationId: spaceId, domain: { $in: wanted }, verifiedAt: { $ne: null } }).select("domain").lean();
  const missing = wanted.filter((d) => !verified.some((v) => v.domain === d));
  if (missing.length) throw new AppError(`Verify these domains first: ${missing.join(", ")}`, 400, "domain_unverified");
  return wanted;
}

export async function listProviders(actorId: string, spaceId: string): Promise<ProviderView[]> {
  if (!(await roleIn(spaceId, actorId))) throw new AppError("Space not found", 404, "not_found");
  await requireDomainOwner(spaceId, actorId);
  const providers = await IdentityProvider.find({ organizationId: new Types.ObjectId(spaceId) }).sort({ name: 1 }).lean<IdentityProviderDocument[]>();
  return providers.map(providerView);
}

export async function saveProvider(actorId: string, spaceId: string, input: ProviderInput, id?: string): Promise<ProviderView> {
  await requireDomainOwner(spaceId, actorId);
  const space = new Types.ObjectId(spaceId);
  const existing = id ? await IdentityProvider.findOne({ _id: Types.ObjectId.isValid(id) ? new Types.ObjectId(id) : null, organizationId: space }) : null;
  if (id && !existing) throw new AppError("Identity provider not found", 404, "not_found");
  if (!existing && (await IdentityProvider.countDocuments({ organizationId: space })) >= MAX_PROVIDERS) throw new AppError(`A space can have up to ${MAX_PROVIDERS} identity providers`, 400, "too_many");
  const name = input.name.trim();
  if (!name || name.length > 80) throw new AppError("Name it (up to 80 characters)", 400, "invalid_request");
  const domains = await checkDomains(space, input.domains);
  // One provider per domain, so a sign-in knows where to go.
  const clash = await IdentityProvider.findOne({ domains: { $in: domains }, _id: { $ne: existing?._id ?? null } }).select("domains").lean();
  if (clash) throw new AppError(`Another identity provider already handles ${clash.domains.filter((d) => domains.includes(d)).join(", ")}`, 409, "domain_taken");
  const preset = input.preset ?? "generic";
  const doc = existing ?? new IdentityProvider({ organizationId: space, protocol: input.protocol });
  if (existing && existing.protocol !== input.protocol) throw new AppError("A provider's protocol can't change; add a new one", 400, "invalid_request");
  Object.assign(doc, { name, preset, domains, enabled: input.enabled ?? doc.enabled ?? true, jit: input.jit ?? doc.jit ?? true });

  if (input.protocol === "oidc") {
    if (!input.oidc?.clientId?.trim()) throw new AppError("Enter the client ID the provider gave you", 400, "invalid_request");
    let issuer: string;
    try {
      issuer = presetIssuer(preset, input.oidc);
    } catch (error) {
      throw new AppError((error as Error).message, 400, "invalid_request");
    }
    httpsUrl(issuer, "Issuer");
    const found = await discover(issuer);
    const secret = input.oidc.clientSecret === undefined ? doc.oidc?.clientSecretSealed ?? null : input.oidc.clientSecret ? sealSecret(input.oidc.clientSecret, `idp:${String(doc._id)}`) : null;
    doc.oidc = { issuer: found.issuer, clientId: input.oidc.clientId.trim(), clientSecretSealed: secret, authorizationEndpoint: found.authorization_endpoint, tokenEndpoint: found.token_endpoint, jwksUri: found.jwks_uri, scopes: presetScopes(preset) };
    doc.saml = null;
  } else {
    const fromMetadata = input.saml?.metadataXml ? parseIdpMetadata(input.saml.metadataXml) : null;
    const idpEntityId = (fromMetadata?.idpEntityId ?? input.saml?.idpEntityId ?? doc.saml?.idpEntityId ?? "").trim();
    const ssoUrl = fromMetadata?.ssoUrl ?? input.saml?.ssoUrl ?? doc.saml?.ssoUrl ?? "";
    if (!idpEntityId) throw new AppError("Enter the IdP's entity ID, or paste its metadata", 400, "invalid_request");
    const certInputs = fromMetadata?.certificates ?? input.saml?.certificates;
    const certificates = certInputs ? certInputs.map(parseCertificate) : doc.saml?.certificates ?? [];
    if (!certificates.length) throw new AppError("Add the IdP's signing certificate", 400, "invalid_request");
    if (certificates.every((c) => c.notAfter.getTime() < Date.now())) throw new AppError("Every certificate given has expired", 400, "invalid_certificate");
    const metadataUrl = input.saml?.metadataUrl === undefined ? doc.saml?.metadataUrl ?? null : input.saml.metadataUrl ? httpsUrl(input.saml.metadataUrl, "Metadata URL") : null;
    doc.saml = { idpEntityId, ssoUrl: httpsUrl(ssoUrl, "Sign-in URL"), metadataUrl, certificates };
    doc.oidc = null;
  }

  if (input.mapping) {
    const teams = input.mapping.teams ?? [];
    if (teams.length) {
      const ids = teams.map((t) => (Types.ObjectId.isValid(t.teamId) ? new Types.ObjectId(t.teamId) : null));
      const found = await SpaceTeam.countDocuments({ _id: { $in: ids.filter(Boolean) }, organizationId: space });
      if (ids.some((x) => !x) || found !== new Set(teams.map((t) => t.teamId)).size) throw new AppError("Map groups to this space's teams", 400, "invalid_request");
    }
    const clean = (v: string | undefined) => (v ?? "").trim().slice(0, 300);
    doc.mapping = {
      email: clean(input.mapping.email),
      firstName: clean(input.mapping.firstName),
      lastName: clean(input.mapping.lastName),
      groups: clean(input.mapping.groups),
      roles: (input.mapping.roles ?? []).slice(0, 50).map((r) => ({ group: r.group.trim().slice(0, 300), role: r.role })),
      teams: teams.slice(0, 50).map((t) => ({ group: t.group.trim().slice(0, 300), teamId: new Types.ObjectId(t.teamId) })),
    };
  }

  await doc.save();
  await noticeToSpaceOwners(spaceId, {
    kind: "sso-changed",
    subject: `Single sign-on ${existing ? "changed" : "added"} in ${await spaceName(spaceId)}`,
    paragraphs: [
      `${await actorLabel(actorId)} ${existing ? "changed" : "added"} the identity provider “${name}” for ${domains.join(", ")}. People at ${domains.length > 1 ? "these domains" : "this domain"} sign in through it${doc.enabled ? "" : " once it's turned on"}.`,
      "Whoever controls an identity provider controls sign-in for its domains. If you didn't expect this, check the space's single sign-on settings now.",
    ],
    action: { label: "Review single sign-on", path: "/spaces" },
  });
  await recordEvent({ action: "sso.provider_saved", stream: orgStream(spaceId), actorId, subjectId: null, data: { organizationId: spaceId, idpId: String(doc._id), protocol: doc.protocol, preset, domains, created: !existing } });
  return providerView(doc.toObject() as IdentityProviderDocument);
}

export async function deleteProvider(actorId: string, spaceId: string, id: string) {
  await requireDomainOwner(spaceId, actorId);
  if (!Types.ObjectId.isValid(id)) throw new AppError("Identity provider not found", 404, "not_found");
  const removed = await IdentityProvider.findOneAndDelete({ _id: new Types.ObjectId(id), organizationId: new Types.ObjectId(spaceId) });
  if (!removed) throw new AppError("Identity provider not found", 404, "not_found");
  const { FederatedIdentity } = await import("@/models/IdentityProvider");
  await FederatedIdentity.deleteMany({ idpId: removed._id });
  await noticeToSpaceOwners(spaceId, {
    kind: "sso-changed",
    subject: `Single sign-on removed in ${await spaceName(spaceId)}`,
    paragraphs: [`${await actorLabel(actorId)} removed the identity provider “${removed.name}” for ${removed.domains.join(", ")}. People at ${removed.domains.length > 1 ? "these domains" : "this domain"} now sign in the usual way.`],
    action: { label: "Review single sign-on", path: "/spaces" },
  });
  await recordEvent({ action: "sso.provider_deleted", stream: orgStream(spaceId), actorId, subjectId: null, data: { organizationId: spaceId, idpId: id } });
}
