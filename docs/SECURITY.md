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

- `JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY` loaded from environment
- `JWT_KEY_ID` identifies the active key in JWKS
- Design allows future rotation by introducing additional kids without changing token issue shape
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
