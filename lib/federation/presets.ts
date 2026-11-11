import type { FederationPreset, FederationProtocol } from "@/models/IdentityProvider";

/**
 * Setup presets: what Entra ID and Okta call things, so an admin only types
 * their tenant and app details. Guides are in docs/SSO.md.
 */

export type PresetDefaults = { email: string; firstName: string; lastName: string; groups: string };

const OIDC_GENERIC: PresetDefaults = { email: "email", firstName: "given_name", lastName: "family_name", groups: "groups" };

const SAML_GENERIC: PresetDefaults = {
  email: "email",
  firstName: "firstName",
  lastName: "lastName",
  groups: "groups",
};

const ENTRA_SAML: PresetDefaults = {
  email: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
  firstName: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
  lastName: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
  groups: "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
};

export function presetDefaults(preset: FederationPreset, protocol: FederationProtocol): PresetDefaults {
  if (protocol === "oidc") return OIDC_GENERIC;
  if (preset === "entra") return ENTRA_SAML;
  return SAML_GENERIC;
}

/** The issuer to discover from, given what the admin typed for the preset. */
export function presetIssuer(preset: FederationPreset, input: { issuer?: string; tenant?: string; oktaDomain?: string }): string {
  if (preset === "entra") {
    const tenant = input.tenant?.trim();
    if (!tenant || !/^[a-z0-9.-]{3,100}$/i.test(tenant)) throw new Error("Enter your Entra tenant ID or domain");
    return `https://login.microsoftonline.com/${tenant}/v2.0`;
  }
  if (preset === "okta") {
    const domain = input.oktaDomain?.trim().replace(/^https:\/\//, "").replace(/\/+$/, "");
    if (!domain || !/^[a-z0-9.-]+\.(okta|oktapreview|okta-emea)\.com(\/oauth2\/[a-z0-9]+)?$/i.test(domain)) throw new Error("Enter your Okta domain, like example.okta.com");
    return `https://${domain}`;
  }
  if (!input.issuer) throw new Error("Enter the provider's issuer URL");
  return input.issuer.trim().replace(/\/+$/, "");
}

/** Extra scopes a preset needs for groups. */
export function presetScopes(preset: FederationPreset): string[] {
  return preset === "okta" ? ["openid", "email", "profile", "groups"] : ["openid", "email", "profile"];
}
