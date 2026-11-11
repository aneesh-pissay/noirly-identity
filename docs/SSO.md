# Single sign-on for organizations

A space (organization) can sign its people in through its own identity provider: Microsoft Entra ID, Okta, or any OpenID Connect or SAML 2.0 IdP. Everything below is in the space's settings, under **Single sign-on**, for owners and admins with the domains area.

## Before you start

1. **Verify your domain.** Under *Business domains*, add it and publish the TXT record. An IdP is trusted only for addresses at the space's verified domains: that's what lets it sign into, and link, existing accounts at those addresses, and why an answer for any other address is refused.
2. Pick **OpenID Connect** where you can (simpler, keys rotate on their own); SAML is there for IdPs and policies that need it.

A space can have up to ten IdPs, each for some of its domains (say, `acme.com` through Entra ID and `acme-labs.com` through Okta). One domain belongs to one IdP.

## Microsoft Entra ID

### OpenID Connect (recommended)

1. In the Entra admin center: **Applications → App registrations → New registration**. Name it "Noirly". Supported accounts: *this organizational directory only*. Redirect URI: **Web**, and the *Redirect URI to register* shown in Noirly after you save (`https://<identity>/api/sso/oidc/callback`).
2. **Certificates & secrets → New client secret.** Copy its value.
3. Optional, for groups: **Token configuration → Add groups claim** (security groups; the ID token gets `groups` with group object IDs).
4. In Noirly: protocol *OpenID Connect*, preset *Microsoft Entra ID*, the **Directory (tenant) ID** from the app's overview, the **Application (client) ID**, and the secret.

Entra's ID tokens may lack `email` for accounts without a mailbox; Noirly falls back to `preferred_username` (the UPN), which must be at your verified domain.

### SAML

1. **Enterprise applications → New application → Create your own → Integrate any other application (non-gallery)**, then **Single sign-on → SAML**.
2. *Basic SAML Configuration*: **Identifier (Entity ID)** and **Reply URL (ACS)** are shown in Noirly once the provider is saved (or upload Noirly's metadata from the link beside it).
3. *Attributes & Claims*: the defaults work (email address, given name, surname). Add a groups claim if you'll map groups.
4. *SAML Certificates*: copy the **App Federation Metadata Url** (Noirly picks up certificate rollovers from it) or download *Federation Metadata XML* and paste it into Noirly with preset *Microsoft Entra ID*.
5. Assign users or groups to the application.

## Okta

### OpenID Connect (recommended)

1. **Applications → Create App Integration → OIDC - OpenID Connect → Web Application.**
2. Sign-in redirect URI: the one Noirly shows (`https://<identity>/api/sso/oidc/callback`). Grant type: *Authorization Code*. Assign the people or groups who should use it.
3. Optional, for groups: **Sign On → OpenID Connect ID Token → Groups claim**: name `groups`, filter *Matches regex* `.*` (or narrower).
4. In Noirly: preset *Okta*, your Okta domain (`example.okta.com`, or `example.okta.com/oauth2/<server>` for a custom authorization server), client ID and client secret. The preset asks for the `groups` scope.

### SAML

1. **Applications → Create App Integration → SAML 2.0.**
2. **Single sign-on URL** = Noirly's ACS URL; **Audience URI (SP Entity ID)** = Noirly's entity ID. Name ID format *Unspecified* or *EmailAddress*.
3. Attribute statements: `email` → `user.email`, `firstName` → `user.firstName`, `lastName` → `user.lastName`; group attribute statement `groups` (filter as you like).
4. From **Sign On → SAML Signing Certificates**, copy the *Metadata URL* or the metadata XML into Noirly (preset *Okta*).

## Other IdPs

*Other* takes an issuer URL (OIDC; Noirly reads `/.well-known/openid-configuration`) or SAML metadata or its three parts (entity ID, HTTP-Redirect sign-in URL, signing certificate). Noirly needs signed assertions (SAML) and a verified `email` claim or attribute.

## Attribute mapping

Leave the claim names empty to use the preset's. Otherwise:

| Field | OIDC default | SAML default (Entra preset) |
| --- | --- | --- |
| Email | `email` (then `preferred_username`) | `email` (`…/claims/emailaddress`) |
| First name | `given_name` | `firstName` (`…/claims/givenname`) |
| Last name | `family_name` | `lastName` (`…/claims/surname`) |
| Groups | `groups` | `groups` (`…/claims/groups`) |

- **Roles:** list IdP groups whose members are the space's *admins*; everyone else signing in through the IdP is a *member*. Owners are never changed by mapping.
- **Teams:** map an IdP group to a team; members are added to and removed from mapped teams at each sign-in. Teams not mapped are left alone.
- Names update from the IdP at each sign-in.

## Accounts: linking and just-in-time creation

- Someone who already has a Noirly account at a verified domain is linked to the IdP on first sign-in (if nobody had confirmed that account's address, what its unconfirmed registrant set up is cleared).
- With **create accounts on first sign-in** (the default), a new person gets an account then, and joins the space as a member. Turn it off to let in only people who already have accounts.

## Requiring single sign-on

Turn on **Require single sign-on for these domains**, and:

- signing in any other way (password, passkey, Google, an emailed link…) is refused for addresses at the IdPs' domains, and the login page sends them straight to the IdP;
- their sessions that didn't come through the IdP end at once.

### Break-glass accounts (when the IdP is down)

Name up to three members as break-glass accounts. Each must already have a second step (an authenticator app or passkey). When the IdP is down they go to `/login?break_glass=1`, and sign in with their password **and** second step; a password alone is refused. Every such sign-in is recorded (`sso.break_glass_used` in the space's activity) and emailed to every owner at once.

Keep their credentials somewhere safe, test them a few times a year, and review the events after each use.

## Certificates

Noirly checks SAML signing certificates daily (the scheduled job, `npm run account:retry-deletions`):

- with a metadata URL, new certificates the IdP publishes are added automatically, before it starts using them;
- 30 days before the last valid certificate expires, owners (and admins with the domains area) get one email;
- an expired certificate is removed once a valid one remains.

Without a metadata URL, add the IdP's new certificate in the settings before the old one expires; both are trusted until then. OIDC keys rotate through the IdP's JWKS with nothing to do.

## For developers

- Start: `GET /api/sso/start?email=<address>` (or `?idp=<id>`) with `return_to`.
- OIDC callback: `/api/sso/oidc/callback` (authorization code with PKCE and nonce).
- SAML: SP metadata at `/api/sso/saml/<id>/metadata`; ACS at `/api/sso/saml/<id>/acs` (HTTP-POST), AuthnRequests by HTTP-Redirect. Responses must answer a request Noirly sent (`InResponseTo`), within 10 minutes, in the browser that started it, once.
- Sessions from SSO have the sign-in method `sso`, `amr: ["fed"]` in ID tokens, and spaces can require it in *Allowed sign-in methods*.
- Settings API: `GET/POST /api/spaces/<spaceId>/sso` (`action`: `save`, `delete`, `enforcement`).
