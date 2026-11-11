# Noirly Identity — Roadmap

**Status:** Living checklist of what to build next, in order
**Companions:** [SECURITY.md](./SECURITY.md) (security model), [INTEGRATION.md](./INTEGRATION.md) (how apps connect)

Each task is a checkbox. When a task ships, tick it and add the date:
`- [x] Secondary email addresses — done 2026-11-04`

Phases are ordered by dependency: the identity event log (Phase 1) is what
security activity, alerts, risk detection and compliance exports read from;
organizations (Phase 7) come before roles, enterprise SSO and provisioning,
which all hang off an organization.
Effort: **S** = days, **M** = 1–2 weeks, **L** = a month or more.

---

## Progress

| Phase | Done |
| --- | --- |
| 1. Profiles and identity history | 9 / 9 |
| 2. Sign-in methods | 7 / 7 |
| 3. Passkeys and multifactor authentication | 7 / 7 |
| 4. Sessions, devices and single sign-on | 6 / 6 |
| 5. OAuth 2.0 and OpenID Connect provider | 6 / 7 |
| 6. Apps and OAuth clients | 7 / 7 |
| 7. Organizations | 7 / 7 |
| 8. Authorization and access control | 7 / 7 |
| 9. Risk detection and account protection | 7 / 7 |
| 10. Account recovery and self-service security | 5 / 5 |
| 11. Privacy, audit and compliance | 7 / 7 |
| 12. Enterprise single sign-on and federation | 8 / 8 |
| 13. Provisioning and identity lifecycle | 8 / 8 |
| 14. Developer platform and automation | 0 / 8 |
| 15. Noirly ecosystem and interface | 0 / 7 |

---

## Already in Identity

What the requirements list asks for that exists today (some only in part):

- One permanent account (`sub`) used by Flow, Ledger, Split and Pulse; profile with first, last and display name, avatar URL and phone field
- Email and password sign-up (Argon2id), email verification, password reset and change; login lockout and shared rate limits by IP and account
- Google OAuth and Google One Tap, with the Google identity linked to the account
- Popup and full-redirect sign-in with safe `returnTo`; native mobile sign-in (password, Google, refresh, logout) and system-browser sign-in with an approval code when MFA is on ([@noirly-dev/identity-mobile](../../noirly-identity-mobile))
- Authenticator app (TOTP) with single-use recovery codes; passkeys as a second factor and for passwordless sign-in; security changes need a sign-in within 5 minutes and sign out other sessions
- Cookie sessions (HTTP-only, hashed at rest) with IP and user agent recorded, revoked on logout and password change
- OAuth 2.0 authorization code with PKCE (S256) required for public clients, state and nonce, exact redirect URI matching, consent screen, short-lived single-use codes; refresh token rotation with reuse detection; token revocation
- OpenID Connect: RS256 ID tokens, discovery document, JWKS (one key, with `kid`), UserInfo, RP-initiated logout
- Public and confidential clients; an admin page to register apps, add origins (Android SHA-1 too), rotate secrets, and enable or disable a client
- Spaces: shared teams (owner, admin, member) that every app mirrors, with an integration API and signed space-changed webhooks (the `Organization` models underneath)
- Account deletion that hands over owned spaces and sends signed, retried account-deleted webhooks to every app; privacy policy
- Nonce-based CSP, CSRF tokens on cookie routes, security headers, NoSQL-injection and security regression tests

---

## Phase 1 — Profiles and identity history

_Everything that reports on an account (security activity, alerts, risk, audit export) reads the event log, so it comes first._

- [x] Identity event log: an append-only, hash-chained record of sign-ins, factor and session changes, and admin actions (M) — done 2026-11-02
- [x] Security activity page: recent sign-ins, new devices and security changes, read from the event log (M) — done 2026-11-02
- [x] Secondary email addresses, each verified, with a choice of primary (M) — done 2026-11-02
- [x] Email address change with re-authentication, a notice to the old address and a window to undo it (S) — done 2026-11-02
- [x] Avatar upload and storage, replacing URL-only avatars (S) — done 2026-11-02
- [x] Locale, timezone and accessibility preferences, shared with apps as standard claims (`locale`, `zoneinfo`) (S) — done 2026-11-02
- [x] Linked identities page: link and unlink Google (and later providers) from settings, never leaving an account without a way to sign in (M) — done 2026-11-02
- [x] Per-app visibility: which apps you've signed in to, what each can see, and when it last did (M) — done 2026-11-02
- [x] Account merge review: when one person has two accounts, a reviewed merge that moves sign-in methods, spaces and app links, and tells apps the old `sub` now maps to the new one (L) — done 2026-11-02

## Phase 2 — Sign-in methods

- [x] Passwordless email magic links, single-use and short-lived, bound to the browser that asked (M) — done 2026-11-02
- [x] Email one-time codes, for sign-in and for verification on devices where links are awkward (S) — done 2026-11-02
- [x] Sign in with Apple (M) — done 2026-11-02
- [x] Sign in with Microsoft and GitHub, on a provider-agnostic linked-account model (M) — done 2026-11-02
- [x] Optional phone verification through an approved SMS provider (never as the only factor) (M) — done 2026-11-04
- [x] Email-first sign-in: enter an email and be routed to the right method (password, passkey, Google, later an organization's SSO) (M) — done 2026-11-04
- [x] Sign-in method settings: which methods an account has, adding and removing them safely (S) — done 2026-11-04

## Phase 3 — Passkeys and multifactor authentication

- [x] FIDO2 hardware security keys alongside platform passkeys, with attestation shown where available (S) — done 2026-11-04
- [x] Authenticator management: rename, last used, device type, and removal rules that keep at least one factor when MFA is required (S) — done 2026-11-04
- [x] Replace recovery codes (a new set voids the old), with a reminder when few are left (S) — done 2026-11-04
- [x] Step-up authentication for apps: honour `max_age`, `prompt=login` and `acr_values`, and return `amr` and `acr` so an app can ask for a fresh second factor before a sensitive action (M) — done 2026-11-04
- [x] MFA enforcement rules: per account, per space or organization, and per app (M) — done 2026-11-04
- [x] Enrollment rules: nudges, a grace period, and sign-in blocked once it ends (S) — done 2026-11-04
- [x] Recovery when a factor is lost (see Phase 10) wired into the MFA challenge screen (S) — done 2026-11-04

## Phase 4 — Sessions, devices and single sign-on

- [x] Devices and sessions page: browser, device, place and last activity, with sign-out of one, several or all (M) — done 2026-11-04
- [x] Per-app sessions: which apps each Identity session signed in to, and signing out of one app without the others (M) — done 2026-11-04
- [x] Configurable idle and absolute session lifetimes, per account policy and later per organization (S) — done 2026-11-04
- [x] Coordinated logout: OIDC back-channel logout to every app the session reached, with front-channel as a fallback (M) — done 2026-11-04
- [x] Refresh tokens tied to their session, so revoking a session revokes them, with reuse detection revoking the whole family everywhere (S) — done 2026-11-04
- [x] Silent single sign-on across Noirly apps (`prompt=none`), and a session check apps can poll cheaply (S) — done 2026-11-04

## Phase 5 — OAuth 2.0 and OpenID Connect provider

- [x] Signing key rotation: several keys in JWKS, scheduled rollover, and retired keys kept until their tokens expire (M) — done 2026-11-04
- [x] Token introspection (RFC 7662) for resource servers (S) — done 2026-11-04
- [x] Audience-restricted access tokens via resource indicators (RFC 8707), as JWTs for APIs that verify offline (M) — done 2026-11-04
- [x] Consent-based claims: UserInfo and ID tokens carry only what the granted scopes allow; the `claims` request parameter (S) — done 2026-11-04
- [x] Discovery metadata kept complete and accurate as each feature lands (grant types, `acr` values, logout endpoints) (S) — done 2026-11-04
- [x] ID token and access token validation guide with negative tests (wrong `aud`, `iss`, expired, bad `nonce`) (S) — done 2026-11-05
- [ ] Pass the OpenID Foundation conformance suite (Basic OP, Config OP, RP-initiated and back-channel logout) (M) — prepared 2026-11-05 (known gaps fixed, `npm run conformance:setup`, runbook in [CONFORMANCE.md](CONFORMANCE.md)); not yet run: needs a reachable HTTPS Identity and a suite (hosted, or local with Docker)

## Phase 6 — Apps and OAuth clients

- [x] Machine-to-machine clients: the client credentials grant, with scopes and audiences (M) — done 2026-11-05
- [x] Custom scopes and API audiences: register an API, its scopes and who may request them (M) — done 2026-11-05
- [x] Client secret rotation with an overlap window (two live secrets), and immediate revocation of a leaked one (S) — done 2026-11-05
- [x] Connected apps for users: what each app was granted, when, and revoking an app's access (and its tokens) (M) — done 2026-11-05
- [x] Development, staging and production configurations per app (redirects, origins, secrets apart) (M) — done 2026-11-05
- [x] App ownership: owners other than the global admin, who manage their own app's settings (M) — done 2026-11-10
- [x] Per-app access policies: anyone, members of chosen spaces or organizations, or an allowlist (M) — done 2026-11-10

## Phase 7 — Organizations

_Spaces become full organizations; everything enterprise builds on this._

- [x] Invitations by email with expiring links and a role, instead of adding by email directly (M) — done 2026-11-10
- [x] Verified business domains (DNS TXT), with auto-join or invite-only policies for that domain (M) — done 2026-11-10
- [x] Ownership transfer and delegated administration (S) — done 2026-11-10
- [x] Teams and groups inside an organization, nested (M) — done 2026-11-10
- [x] Organization switcher with isolated contexts: an `org_id` claim, and tokens scoped to one organization (M) — done 2026-11-10
- [x] App access per organization: which Noirly apps an organization uses, and who in it may open them (M) — done 2026-11-10
- [x] Organization security policies: required MFA, allowed sign-in methods, session lifetimes (M) — done 2026-11-10

## Phase 8 — Authorization and access control

_Identity holds roles and permissions; apps still enforce them on their own data._

- [x] Roles and granular permissions per resource and action, with organization-scoped assignments (L) — done 2026-11-10
- [x] Permissions delivered to apps as token claims or a permissions API, default-deny (M) — done 2026-11-10
- [x] Conditional rules: attribute-based conditions (department, region, device trust, time) on a permission (L) — done 2026-11-10
- [x] Short-lived elevated access: request, approve and auto-expire extra permissions (M) — done 2026-11-10
- [x] Service accounts with limited, delegated privileges and their own credentials (M) — done 2026-11-10
- [x] Policy simulation: "can this person do this, and why", for troubleshooting (M) — done 2026-11-10
- [x] Permission audit trail: every grant, change and removal in the event log (S) — done 2026-11-10

## Phase 9 — Risk detection and account protection

- [x] Compromised password checks against breach corpora (k-anonymity range lookups), at sign-up, password change and sign-in (S) — done 2026-11-10
- [x] Device-aware rate limiting on top of IP and account limits, against credential stuffing (S) — done 2026-11-10
- [x] Sign-up abuse protection: a privacy-friendly challenge, disposable-email blocking and velocity limits (M) — done 2026-11-10
- [x] Unusual sign-in detection: new device, new country, impossible travel (M) — done 2026-11-10
- [x] Adaptive MFA: ask for a second factor when risk signals say so, even when it's optional (M) — done 2026-11-10
- [x] Account takeover containment: lock, sign out everywhere, revoke app tokens and force a reset, from one admin action (M) — done 2026-11-10
- [x] Security alerts by email for important events: new device, factor added or removed, password or email changed (S) — done 2026-11-10

## Phase 10 — Account recovery and self-service security

- [x] Lost-passkey and lost-authenticator recovery through verified recovery methods, with a waiting period and notices on every channel (M) — done 2026-11-10
- [x] Verified recovery methods: a secondary email and optional phone, kept separate from sign-in (S) — done 2026-11-10
- [x] Account lock and unlock: "freeze my account" for the user, and admin locks with a reason (S) — done 2026-11-10
- [x] High-risk recovery review: a queue where an admin checks recoveries the risk signals flag (M) — done 2026-11-10
- [x] Account closure with a grace period to undo it, an offered data export first, and revocation everywhere (S) — done 2026-11-10

## Phase 11 — Privacy, audit and compliance

_Needs the Phase 1 event log._

- [x] Configurable audit retention, and export of authentication and admin logs (S) — done 2026-11-10
- [x] Admin audit search, with alerts on chosen events (M) — done 2026-11-10
- [x] Privacy dashboard: what Identity holds about you, the apps you've consented to, and revoking consent (M) — done 2026-11-10
- [x] Personal data export across Noirly apps: Identity's data plus each app's export, in one request (L) — done 2026-11-10
- [x] Coordinated deletion status: which apps have confirmed an account's deletion, and retrying those that haven't (M) — done 2026-11-10
- [x] Claim minimization review: every app gets only the claims it needs (S) — done 2026-11-10
- [x] Policy documents, a controls list and evidence for compliance reviews (M) — done 2026-11-10

## Phase 12 — Enterprise single sign-on and federation

_Needs Phase 7 organizations and verified domains._

- [x] SAML 2.0 federation as a service provider, with signed assertions and metadata exchange (L) — done 2026-11-10
- [x] External OIDC identity provider connections (M) — done 2026-11-10
- [x] Microsoft Entra ID and Okta setup presets and guides (S) — done 2026-11-10
- [x] Domain-based SSO enforcement: a verified domain must sign in through its organization's IdP (S) — done 2026-11-10
- [x] Several identity providers per organization (S) — done 2026-11-10
- [x] Claims, roles and attribute mapping from the IdP to Identity profiles and organization roles (M) — done 2026-11-10
- [x] Federation certificate expiry monitoring and rotation (S) — done 2026-11-10
- [x] Emergency access when the IdP is down: break-glass accounts, controlled and audited (M) — done 2026-11-10

## Phase 13 — Provisioning and identity lifecycle

- [x] SCIM 2.0 user and group provisioning (L) — done 2026-11-10
- [x] Just-in-time provisioning on first enterprise sign-in (S) — done 2026-11-10
- [x] Automatic offboarding: a deactivated user loses sessions and tokens at once, and apps are told (M) — done 2026-11-10
- [x] Directory group sync to organization teams and roles (M) — done 2026-11-10
- [x] Lifecycle webhooks (user created, updated, deactivated, deleted; membership changed), signed and retried, on `@noirly-dev/webhooks` (M) — done 2026-11-10 (built in `lib/webhooks/lifecycle.ts`, ready to move into `@noirly-dev/webhooks`, which isn't published yet)
- [x] Duplicate user detection and provisioning reconciliation (M) — done 2026-11-10
- [x] Bulk invitation, CSV import and bulk management (M) — done 2026-11-10
- [x] Reactivating memberships and deactivated users (S) — done 2026-11-10

## Phase 14 — Developer platform and automation

- [ ] TypeScript, React and Next.js SDKs (sign-in, session, token refresh, step-up) (L)
- [ ] Native app guidance alongside the mobile SDK (S)
- [ ] Self-service developer console for registering and managing OAuth clients (needs Phase 6) (M)
- [ ] Management API with scoped administration tokens (L)
- [ ] Webhook console: endpoints, signing secrets, delivery log and replay (S)
- [ ] CLI, example projects and integration templates (M)
- [ ] Sandbox environment and a protocol test suite apps can run (M)
- [ ] Auth analytics, monitoring and developer diagnostics (sign-in funnel, error rates, a token debugger) (M)

## Phase 15 — Noirly ecosystem and interface

- [ ] Branded sign-in with dark, light and Noirly gold themes (S)
- [ ] Localization (Hindi first) and an accessibility pass on every authentication flow (M)
- [ ] Cross-app account and organization switcher, shared through `@noirly-dev/ui` (M)
- [ ] App portal: Flow, Ledger, Split and Pulse in one place, with the ones you use first (M)
- [ ] Central notification and security preferences that apps read (M)
- [ ] Subscriptions and product entitlements, delivered to apps as claims (L)
- [ ] Identity operations dashboard: uptime, incidents and status page (M)

---

## Cross-app

- **Spaces are the team list for every app.** Flow, Ledger and Split link their own teams to a space and mirror its members; Phase 7 grows spaces into organizations without breaking that link.
- **Apps own their data; Identity owns who you are.** Apps keep enforcing permissions on their own records (Ledger's custom roles, Flow's workspace checks). Phase 8 gives them roles and claims to read, not a replacement.
- **Each app adopts new protocol features as they land:** step-up (`acr`, `max_age`) for sensitive actions such as Ledger's two-person approvals, back-channel logout, and lifecycle webhooks next to the existing account-deleted and space-changed ones.
- **Ledger and the other apps link to Identity** for passkeys, MFA and devices rather than building their own.
- **Mobile:** [noirly-identity-mobile](../../noirly-identity-mobile) follows each sign-in and MFA change.

## Not planned

| Item | Why |
| --- | --- |
| Phone number as the only sign-in factor | SMS is too easy to take over; phone stays an optional verification and recovery method |
| Running our own SMS or email delivery infrastructure | Approved providers handle delivery; Identity handles who and when |
| App data stored in Identity | Identity is authentication, profiles, organizations and permissions; each app keeps its own data |
| Implicit and password (ROPC) OAuth grants | Deprecated by OAuth 2.1; Authorization Code with PKCE covers browsers and native apps |
