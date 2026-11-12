# Security documentation — Noirly Identity

Authentication is security-critical. This document summarizes controls and operational rules.

## Password storage

- Algorithm: **Argon2id**
- Parameters: memory 19456 KiB, time cost 2, parallelism 1
- Plaintext passwords are never stored or logged
- Password change revokes other sessions

## Client secrets

- Confidential client secrets are hashed with Argon2id
- Public clients have no secret and must use PKCE
- Secrets are only shown during explicit client provisioning; the development seed does not print credentials

## Sessions

- Session tokens are random (`base64url`) and stored as SHA-256 hashes
- Cookies: `HttpOnly`, `SameSite=Lax`, `Secure` in production
- CSRF: double-submit cookie (`noirly_csrf`) + `X-CSRF-Token` on cookie-auth mutations
- Logout revokes the session and associated OAuth tokens for that session

## OAuth / OIDC

- Authorization Code only (`response_type=code`)
- PKCE `S256` required for public clients and when `requirePkce` is set
- `state` required
- `nonce` supported and embedded in ID tokens
- Redirect URIs and post-logout URIs: exact allow-list match only
- Authorization codes: short TTL, single-use, bound to client + redirect URI + PKCE
- Access tokens: opaque, hashed at rest, revocable
- ID tokens: RS256 JWT, private key from env only
- Refresh tokens: hashed, rotated, reuse detection revokes the token family

## Rate limiting & brute force

- Generic per-IP rate limits on sensitive endpoints
- Login attempt counters with lockout windows
- Shared MongoDB counters enforce limits across app instances and fail closed when unavailable
- Prefer generic auth error messages where appropriate

## Headers

API responses set:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Cache-Control: no-store` (API)

Middleware applies baseline browser hardening headers.

## Logging rules

Never log:

- passwords
- access tokens
- refresh tokens
- authorization codes
- client secrets
- private keys
- raw session tokens

Development email previews redact sensitive tokens. Production requires the SMTP provider. Do not log full email payloads or recipient addresses.

For real delivery, set `EMAIL_PROVIDER=smtp` and configure Nodemailer SMTP settings (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `EMAIL_FROM`). Never log SMTP passwords.

## Key management

- Signing keys live in MongoDB (`SigningKey`), private halves sealed with AES-256-GCM under `ENCRYPTION_KEY` and bound to their `kid`
- `JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY` / `JWT_KEY_ID` only seed the first key; after that the database is the source of truth
- Rollover (`npm run keys:rotate`, run daily): a `next` key is published in JWKS `SIGNING_KEY_PREPUBLISH_HOURS` (default 48) before it signs; every `SIGNING_KEY_ROTATION_DAYS` (default 90) it becomes active and the old key retires; retired keys stay published until every token they signed has expired (at least a day), then are removed
- A leaked key: `npm run keys:rotate -- --now --drop-old` (or `POST /api/admin/keys` with `dropOld`) switches at once and unpublishes the old key, so what it signed stops verifying. Instances pick up a rotation within a minute
- Every rotation and removal is in the hash-chained event log (`signing_key.rotated`, `signing_key.removed`)
- JWKS never exposes private key material

## Email tokens

Verification and password-reset tokens:

- cryptographically random
- hashed at rest
- expiring
- single-use

## Data model notes

- User emails are normalized to lowercase and unique-indexed
- TTL indexes expire auth codes, tokens, and timed records where appropriate
- Organization models exist for future multi-tenant expansion without changing core authN

## MFA and passkeys

- Authenticator enrollment requires a recent sign-in and confirmation of a valid code.
- Authenticator secrets are encrypted with AES-256-GCM using `ENCRYPTION_KEY`; recovery codes are hashed and consumed atomically.
- Passkeys require user verification and validate the expected origin, RP ID, challenge and credential counter. A verified passkey completes MFA.
- Enabling either method makes subsequent password and Google sign-ins require a second factor. Passkeys can also sign in directly.
- Security changes revoke other sessions and OAuth tokens. Recovery codes are displayed once.
- MFA is optional per account; enrollment is not mandatory for every user.

See [SECURITY-ROLLOUT.md](./SECURITY-ROLLOUT.md) for deployment requirements and limitations.

## Risk detection and account protection

- **Breached passwords:** checked against Have I Been Pwned by k-anonymity (only five characters of the password's SHA-1 leave Identity; responses are padded) when a password is chosen (sign-up, change, reset, adding one) and refused if found. A sign-in with one flags the account and emails its owner. The check fails open if the service can't be reached. `BREACHED_PASSWORD_CHECK=off` disables it.
- **Device-aware limits:** each browser gets a random `noirly_device` cookie (native apps send `X-Noirly-Device`). Password sign-ins are limited per device (20 in 15 minutes) and per address (60) across all accounts, on top of the per-account and per-address-and-account limits, against credential stuffing.
- **Sign-up protection:** the web form solves a proof-of-work challenge (about a second of hashing; signed, short-lived, single use; `SIGNUP_POW_BITS`), disposable email domains are refused (`DISPOSABLE_EMAIL_DOMAINS` adds more), and new accounts are limited per address (5 an hour) and per device (3).
- **Unusual sign-ins:** each sign-in is compared with the account's last 50 (kept a year): a new device, a new country, or a different country under two hours after the last sign-in (impossible travel). Unusual ones are logged and emailed to the owner.
- **Adaptive second step:** a high-risk sign-in (impossible travel, or a new device in a new country) by an account without a second step must enter a code emailed to it. Accounts with a second step always use it.
- **Containment:** `POST /api/admin/accounts` (`contain`, after a fresh admin sign-in) locks an account, signs it out everywhere (apps told by back-channel logout), revokes every app token and removes the password; `unlock` reopens it and emails a reset link. UI: `/admin/security`.
- **Alerts:** emailed from the event log for unusual sign-ins, factors added or removed, password changes, resets, additions and removals, email addresses added or removed, and newly linked sign-in providers.

## Recovery and self-service security

- **Recovery methods:** a recovery address (proved with a code; never one used to sign in) and the verified phone. Neither ever signs anyone in, and apps never see them. Changing them needs a fresh sign-in, and the owner is alerted.
- **Lost second step:** from the verification screen, a code sent to a recovery method proves it's the owner; then removing the second steps waits 24 hours (72 without a recovery method), and every address, the recovery address and the phone are told, each with a link to stop it.
- **Review of risky recoveries:** one started from somewhere unusual (a new device in a new country, or impossible travel) can't be finished until an admin approves it (`/admin/security`, `GET`/`POST /api/admin/recoveries`); the owner hears either way.
- **Freezing:** the owner freezes the account from the account page or from the link in any security alert (no sign-in needed): every device signed out, every app token revoked, no sign-in. Unfreezing is asked for by email and happens a day after confirming, with a link on every channel to keep it frozen. Admins lock with a reason (`POST /api/admin/accounts`, `lock`), which only an admin unlocks.
- **Closing:** closing the account (web) signs out and revokes everywhere at once; it's deleted for good after 14 days (with its data in every Noirly app), and every address gets a link to undo it until then. `GET /api/auth/export` downloads everything Identity holds, offered first. Native apps' account deletion (`/api/mobile/...` with an access token) still deletes at once, as app stores expect.


## Enterprise single sign-on (federation)

See [SSO.md](SSO.md) for setup.

- An organization's IdP is trusted only for addresses at the organization's DNS-verified domains, one IdP per domain. An answer for any other address is refused, so an IdP can't sign into accounts it doesn't own.
- OIDC: authorization code with PKCE (S256), `state` and `nonce`; ID tokens verified against the IdP's JWKS (re-read once on an unknown key), issuer, audience and expiry checked; `email_verified: false` is refused. Client secrets are sealed with `ENCRYPTION_KEY`.
- SAML (node-saml): signed assertions required, against the configured certificates only (expired ones are ignored); audience, recipient, issuer, validity window (60 s skew) and `InResponseTo` checked; request ids are single-use and expire after 10 minutes; assertion ids are remembered so a response can't be replayed (both in MongoDB, `saml_cache`).
- Both flows carry a signed, HttpOnly `noirly_sso` cookie (10 minutes) from start to finish. The SAML POST from the IdP is parked server-side for 2 minutes and finished by a same-site GET that carries that cookie, so an answer only signs in the browser that asked (no login CSRF).
- Enforcement is checked where every session is made (`createSession`), so no sign-in path skips it; turning it on ends existing non-SSO sessions at those domains.
- Break-glass accounts: at most three, members with a second step; they must use it (password alone is refused); each use is an `sso.break_glass_used` event and an email to every owner.
- Certificates: rollovers from the IdP's metadata URL are picked up daily; owners are warned 30 days before the last valid one expires.

## Provisioning and lifecycle

See [PROVISIONING.md](PROVISIONING.md).

- SCIM tokens are per space, shown once, stored as SHA-256 hashes, rate limited (600 requests a minute each), and made and revoked only by owners or admins with the domains area.
- A space provisions, adopts and locks only identities at its DNS-verified domains; everyone else it can only remove from the space. Provisioning never adds an outside address to a space.
- Deactivating an owned identity locks it (`lockKind: deprovisioned`, the space recorded), revokes every token and session, and tells apps (back-channel logout and lifecycle webhooks). The owner can't lift it with a self-freeze; only the space (reactivation) or an Identity admin can.
- Lifecycle webhooks are signed Security Event Tokens, kept in an outbox (`webhook_deliveries`, a week) and retried with backoff; they carry ids and what changed, never profile data.

## Notices

Plain emails (`lib/notifications/notices.ts`) for changes people should hear about. They carry no secret or sign-in link, and never fail the change they report.

| When | Who hears |
| --- | --- |
| An identity provider is added, changed or removed; SSO enforcement or break-glass accounts change | The space's owners, and admins with the domains area |
| A SCIM provisioning token is made or revoked (the token itself is never emailed) | The same |
| SSO enforcement signs someone out (their tokens are revoked and apps told, as for any sign-out) | That person, with how to sign in now |
| An organization makes an account (first SSO sign-in, or SCIM), or adopts an existing one into its space | That person: who made it, how to sign in, and that the organization manages it |
| An organization deactivates or reactivates someone | That person: "turned off" for an identity it owns, "no longer have access" otherwise |
| After every retry, an app never confirmed account deletions, or stopped accepting lifecycle events | Identity admins, one summary per scheduled run |
| `npm run compliance:evidence -- --notify` finds a failing control | Identity admins |

Identity admins can also email anyone on any event with audit alert rules (`/admin/audit` → Alerts).
