import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { inflateRawSync } from "node:zlib";
import { SignedXml } from "xml-crypto";

/** A pretend SAML IdP for tests: answers an AuthnRequest with a signed assertion. */

const fixture = (name: string) => readFileSync(resolve(__dirname, "../fixtures", name), "utf8");
export const IDP_CERT = fixture("saml-idp.crt");
const IDP_KEY = fixture("saml-idp.key");
export const NEXT_IDP_CERT = fixture("saml-idp-next.crt");

/** The ID of the AuthnRequest in a redirect-binding URL. */
export function requestIdOf(url: string): string {
  const raw = new URL(url).searchParams.get("SAMLRequest")!;
  const xml = inflateRawSync(Buffer.from(raw, "base64")).toString("utf8");
  return /\bID="([^"]+)"/.exec(xml)![1]!;
}

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;");

export function samlResponse(input: {
  idpEntityId: string;
  acsUrl: string;
  audience: string;
  inResponseTo: string;
  nameId: string;
  attributes: Record<string, string | string[]>;
  tamper?: (xml: string) => string;
}): string {
  const now = new Date();
  const later = new Date(now.getTime() + 5 * 60_000).toISOString();
  const earlier = new Date(now.getTime() - 60_000).toISOString();
  const id = (p: string) => `_${p}${Math.random().toString(16).slice(2)}`;
  const attrs = Object.entries(input.attributes)
    .map(([name, value]) => `<saml:Attribute Name="${esc(name)}">${(Array.isArray(value) ? value : [value]).map((v) => `<saml:AttributeValue>${esc(v)}</saml:AttributeValue>`).join("")}</saml:Attribute>`)
    .join("");
  const xml =
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id("r")}" Version="2.0" IssueInstant="${now.toISOString()}" Destination="${esc(input.acsUrl)}" InResponseTo="${input.inResponseTo}">` +
    `<saml:Issuer>${esc(input.idpEntityId)}</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
    `<saml:Assertion ID="${id("a")}" Version="2.0" IssueInstant="${now.toISOString()}">` +
    `<saml:Issuer>${esc(input.idpEntityId)}</saml:Issuer>` +
    `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">${esc(input.nameId)}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="${input.inResponseTo}" NotOnOrAfter="${later}" Recipient="${esc(input.acsUrl)}"/></saml:SubjectConfirmation></saml:Subject>` +
    `<saml:Conditions NotBefore="${earlier}" NotOnOrAfter="${later}"><saml:AudienceRestriction><saml:Audience>${esc(input.audience)}</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${now.toISOString()}" SessionIndex="${id("s")}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
    `<saml:AttributeStatement>${attrs}</saml:AttributeStatement>` +
    `</saml:Assertion></samlp:Response>`;
  const sig = new SignedXml({
    privateKey: IDP_KEY,
    publicCert: IDP_CERT,
    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
  });
  sig.addReference({
    xpath: "//*[local-name(.)='Assertion']",
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
  });
  sig.computeSignature(xml, { location: { reference: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']", action: "after" } });
  const signed = input.tamper ? input.tamper(sig.getSignedXml()) : sig.getSignedXml();
  return Buffer.from(signed).toString("base64");
}
