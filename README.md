# Noirly Identity

Central authentication and OpenID Connect (OIDC) provider for the Noirly application ecosystem.

One Noirly account authenticates users across future products (CRM, Flow, Docs, Atlas, and more) using standard **OAuth 2.0 Authorization Code + PKCE** and **OpenID Connect**. For React Native (native UI, no WebView), use [@noirly-dev/identity-mobile](docs/INTEGRATION.md#11-native-mobile-sdk-no-webview).

```text
                    Noirly Identity
                    auth.noirly.com
                          |
          +---------------+---------------+
          |               |               |
          v               v               v
      Noirly CRM      Noirly Flow     Noirly Docs
```

## Stack

- Next.js (App Router) + TypeScript
- MongoDB + Mongoose
- Argon2id password hashing
- Jose (RS256 ID tokens / JWKS)
- Zod request validation

## Quick start

```bash
npm install
npm run env:generate          # creates .env.local with RSA keys + secrets
# start MongoDB locally, then:
npm run db:seed               # test user + NoirlyCRM OAuth client
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

### Useful scripts

| Script | Purpose |
| --- | --- |
| `npm run dev` | Start Identity locally |
| `npm run env:generate` | Generate `.env.local` secrets + RS256 keys |
| `npm run db:seed` | Seed test user + NoirlyCRM client |
| `npm run conformance:setup` | Clients and a test account for the OpenID conformance suite ([docs/CONFORMANCE.md](docs/CONFORMANCE.md)); `-- --remove` afterwards |
| `npm run keys:rotate` | Signing key rollover; run daily (`-- --now`, `-- --now --drop-old` for a leaked key) |
| `npm run account:retry-deletions` | Scheduled job: retention, closed accounts, deletion, merge and logout notices, data exports, elevations |
| `npm run compliance:evidence` | Compliance evidence as JSON; exits 1 if a control fails ([docs/compliance](docs/compliance/README.md)) |
| `npm test` | Run security-critical tests |
| `npm run typecheck` | TypeScript check |
| `npm run lint` | ESLint |
| `npm run build` | Production build |

## Architecture overview

| Concern | Location |
| --- | --- |
| Auth APIs | `app/api/auth/*` |
| OAuth endpoints | `app/api/oauth/*` |
| OIDC endpoints | `app/api/oidc/*`, `app/.well-known/*` |
| Domain logic | `lib/auth`, `lib/oauth`, `lib/oidc`, `lib/sessions`, `lib/tokens` |
| Models | `models/*` |
| Validation | `lib/validation/schemas.ts` |
| Email abstraction | `lib/email` |

Sessions for the Identity UI use **HTTP-only cookies** (hashed at rest). Access tokens for APIs are **opaque** and stored hashed. ID tokens are **RS256 JWTs**.

## API surface

### Auth (cookie session)

- `GET /api/auth/csrf`
- `POST /api/auth/register`
- `POST /api/auth/discover` — email-first sign-in: the ways to offer an address (unknown addresses look like password accounts)
- `POST /api/auth/login`
- `POST /api/auth/magic-link` — email a sign-in link and code that work only in this browser; `POST /api/auth/magic-link/verify` signs in with the link, `POST /api/auth/magic-link/code` with the code
- `GET /api/auth/apple` — Sign in with Apple (`intent=link` links it to the signed-in account); Apple posts back to `/api/auth/apple/callback`. Native apps: `POST /api/mobile/apple`
- `GET /api/auth/oauth/microsoft`, `GET /api/auth/oauth/github` — sign in with Microsoft or GitHub (`intent=link` links instead); they come back to `.../callback`
- `POST /api/auth/verify-email/code` — confirm a new account's address with the code from its verification email (`{ email, code }`)
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `PATCH /api/auth/me`
- `POST /api/auth/change-password`
- `POST /api/auth/password` — add a password to an account without one (`set`), or remove it (`remove`, never the last way in)
- `GET /api/auth/activity` — your own sign-ins and security changes (`kind`, `before`)
- `GET /api/auth/emails`, `POST /api/auth/emails` — your email addresses: `add`, `resend`, `remove`, `make-primary`
- `POST /api/auth/recovery` — lost second step, from the verification screen: `status`, `start` (a 24-hour wait, every address told), `finish`; `POST /api/auth/recovery/cancel` stops it from the emailed link
- `POST /api/auth/email-change/undo` — undo a primary address change with the link sent to the old address
- `POST /api/auth/avatar` (the image as the body), `DELETE /api/auth/avatar` — your profile photo
- `GET /api/auth/merge`, `POST /api/auth/merge` — merge another account into yours: `request`, `complete`, `cancel`; `POST /api/auth/merge/confirm` confirms from the link sent to the other account
- `GET /api/auth/phone`, `POST /api/auth/phone` — an optional verified phone number: `start` texts a code, `confirm`, `remove` (never a way to sign in)
- `GET /api/auth/sessions`, `POST /api/auth/sessions` — your signed-in devices; `sign-out` chosen ones or `sign-out-others` (their app sign-ins end too), or `sign-out-app` to end one app's sign-ins on one device (`sessionId`) or every device, leaving the rest signed in
- `GET /api/auth/sessions/policy`, `POST /api/auth/sessions/policy` — how long your sessions last: `idleSeconds` (sign out after going unused, 15 minutes to 30 days, or `null`) and `absoluteSeconds` (sign out after this long however busy, an hour up to `SESSION_TTL_SECONDS`, or `null` for that default). Applies to live sessions at once; changing it needs a fresh sign-in
- `GET /api/auth/apps`, `POST /api/auth/apps` — apps that have signed you in: what each can see and since when, when it last did, whether it's signed in now; `remove` takes an app's access away (its tokens end, it's signed out by back-channel logout, and it must ask on the consent screen again)
- `GET /api/auth/identities`, `DELETE /api/auth/identities` — your ways to sign in; unlink a provider (never the last way in). Link Google with `GET /api/auth/google?intent=link`
- `POST /api/spaces/:spaceId/members` — invite someone by email with a role (admins; owners for owners): a week-long link they open signed in to an account with that address. `GET /api/spaces/:spaceId/invitations`, `DELETE .../invitations/:id` to list and withdraw; `GET /api/invitations?token=` previews one, `POST /api/invitations` joins
- `GET /api/spaces/:spaceId/domains`, `POST .../domains` — a space's business domains (owners): `add`, `verify` (DNS TXT `_noirly-verify.<domain>`), `policy` (`invite_only` or `auto_join`), `remove`. `GET /api/spaces/joinable` and `POST /api/spaces/:spaceId/join` let people with a confirmed address at an auto-join domain join without an invitation
- `POST /api/spaces/:spaceId/transfer` — hand a space to another member (owners): they become owner, you an admin. `PATCH /api/spaces/:spaceId/members/:userId` with `adminAreas` (`members`, `settings`, `domains`, `apps`, or `null` for all) limits what an admin may do; domains are owners' unless delegated
- `GET /api/spaces/:spaceId/teams`, `POST .../teams` — teams inside a space, nested up to 5 deep (`create`, `update` to rename or move, `delete`, `add-member`, `remove-member`; admins with the members area). Someone in a sub-team counts as in the teams above it
- `GET /api/spaces/:spaceId/apps`, `POST .../apps` — which apps the organization uses (`mode`: `open` or `listed`) and who may open each (`set` with `everyone`, `admins` or `teams`; `remove`). Applies when an app is opened in the organization (`organization=`), and at every refresh
- `GET /api/spaces/:spaceId/security`, `PATCH .../security` — the organization's allowed sign-in methods (opening an app in it needs a sign-in that used one) and session limits (members get the strictest of theirs and every organization's, live sessions included); a second step stays `requireMfa` on the space
- `GET /api/spaces/:spaceId/access`, `POST .../access` — roles and who holds them (`save-role`, `delete-role`, `assign` with resource, conditions and expiry, `unassign`, `set-attributes`, `time-zone`; admins with the access area). `POST .../access/simulate` explains a decision. `GET`/`POST .../access/requests` for temporary access (`request`, `approve`, `deny`, `cancel`). `GET`/`POST .../service-accounts` (`create`, `rotate`, `disable`). Every change is in the organization's event log (`org:<id>`)
- `POST /api/authz/check`, `GET /api/authz/permissions` — for apps: may the person or service account behind this access token do this, now (default deny)
- `GET /api/avatars/:userId/:hash` — a profile photo, public and cached for good (the `picture` claim points here)
- `POST /api/auth/verify-email`
- `POST /api/auth/forgot-password`
- `POST /api/auth/reset-password`

Cookie-authenticated mutating routes require `X-CSRF-Token` matching the `noirly_csrf` cookie.

### Admin (cookie session, `admin` role)

- `GET /api/admin/clients`
- `POST /api/admin/clients` — create or add origins for any Noirly app
- `PATCH /api/admin/clients/:clientId` — add origins, rotate secret (`rotateSecret`, with `secretOverlapSeconds` for how long the old one still works, default a day; `dropPreviousSecret` to end that early; `revokeMachineTokens` for a leaked secret), enable/disable, `requireMfa` (every sign-in to the app needs a second step), `backchannelLogoutUri` / `frontchannelLogoutUri` (coordinated logout, see INTEGRATION.md), `dataExportUri` (personal data export), `lifecycleWebhookUri` / `lifecycleEvents` (lifecycle webhooks)
- `GET /api/admin/resources`, `POST /api/admin/resources` — APIs that accept Identity tokens (RFC 8707): identifier, own scopes, token lifetime (60–3600 s), which apps may ask for people (`allowedClientIds`) and which may call it as themselves (`machineGrants`, the client credentials grant)
- `GET /api/admin/keys`, `POST /api/admin/keys` — signing keys (never private halves); `rotate` now, with `dropOld` for a leaked key (fresh sign-in needed)
- `POST /api/admin/clients/:clientId/environments` — add a `development`, `staging` or `production` environment to an app: its own client ID (`<app>-dev`, `<app>-staging`), secret and redirect URIs. Production and staging redirect only to https on real hosts; development only to localhost
- `GET /api/admin/events` — the identity event log, newest first (`stream`, `action`, `subjectId`, `before`)
- `GET /api/admin/events/verify?stream=` — check a stream's hash chain (`user:<id>`, `admin`, `system`)
- `GET /api/admin/deletions`, `POST /api/admin/deletions` — which apps confirmed each account deletion (90 days), and retrying one now (`/admin/deletions`)
- `GET /api/admin/claims`, `POST /api/admin/claims` — claim minimization review: scopes each app may ask for against those people granted; trim unused ones (`/admin/claims`)
- `GET /api/admin/evidence` — live compliance evidence (`?download=1`)

Who may use an app: `accessPolicy` on the same PATCH (`{ mode: "anyone" }`, `{ mode: "spaces", spaces: [slugs] }` or `{ mode: "allowlist", emails: [...] }`), checked at sign-in and at every token exchange and refresh. Someone left out sees `/no-access` (or the app gets `access_denied` with `prompt=none`).

App owners (set with `owners` on `PATCH /api/admin/clients/:clientId`, by the emails of verified accounts) manage their own app there too: settings, redirects, environments, secrets and co-owners; registering and deleting apps stay with admins.

UI: sign in as an admin and open `/clients` (apps) or `/apis` (APIs, their scopes, and which apps may ask for them). Grant admin with:

```bash
npm run user:promote-admin -- --email=you@example.com
```

That writes to the MongoDB in Identity’s `MONGODB_URI` (local `.env.local` for local, Atlas for production).

### OAuth / OIDC

- `GET /api/oauth/authorize`
- `POST /api/oauth/consent`
- `POST /api/oauth/token`
- `POST /api/oauth/revoke`
- `POST /api/oauth/introspect` — RFC 7662: is a token live, and what does it allow (confidential clients; refresh tokens only to their own app)
- `GET /api/oidc/userinfo`
- `GET /api/oidc/logout`
- `POST /api/oidc/session` — is the Identity session behind a sign-in still going (access token, or a confidential app's credentials and `sid`); never counts as activity
- `GET /.well-known/openid-configuration`
- `GET /.well-known/jwks.json`

## Integrating a Noirly application

See **[docs/TOKEN-VALIDATION.md](docs/TOKEN-VALIDATION.md)** for checking every kind of token Identity signs (with [reference code](docs/examples/verify-tokens.ts)), and **[docs/INTEGRATION.md](docs/INTEGRATION.md)** for the full guide (client registration, PKCE, token exchange, UserInfo, logout, refresh rotation, errors).

High-level flow:

```text
NoirlyCRM
   |
   | GET /api/oauth/authorize  (+ PKCE, state, nonce)
   v
Noirly Identity  (login + consent)
   |
   | redirect ?code=&state=
   v
NoirlyCRM
   |
   | POST /api/oauth/token
   v
access_token + id_token (+ refresh_token if offline_access)
```

## Security

See **[docs/SECURITY.md](docs/SECURITY.md)**.

Highlights:

- Argon2id for passwords and confidential client secrets
- Exact redirect URI matching (no open redirects)
- PKCE (S256), state, nonce
- Short-lived single-use authorization codes
- Refresh token rotation + reuse detection: tokens end with their session, and reuse revokes the whole family, its access tokens and the app's session
- Session revocation on logout / password change, passed on to every app the session reached (OIDC back-channel logout, front-channel as a fallback)
- Rate limiting and login lockout
- Provisioning: SCIM 2.0 users and groups, just-in-time accounts, offboarding and reactivation, bulk invitations and CSV import, lifecycle webhooks ([docs/PROVISIONING.md](docs/PROVISIONING.md))
- Enterprise single sign-on for spaces: Entra ID, Okta, any OIDC or SAML 2.0 IdP, with domain enforcement, attribute mapping and break-glass access ([docs/SSO.md](docs/SSO.md))
- No secrets in logs

## Organizations (prepared)

Models `Organization` and `OrganizationMembership` (`owner` | `admin` | `member`) are present for future multi-tenant features. Product-specific authorization should live in each app, using Identity only as the authN source of truth.

## License

Private — Noirly.
