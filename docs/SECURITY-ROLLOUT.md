# Security rollout: Identity, Flow Web and Flow Mobile

These changes are local implementation work. They have not been deployed or exercised against production accounts or databases.

## Deployment order

1. Review environment configuration and back up the Identity database and encryption key.
2. Deploy Identity with its updated dependencies, MFA endpoints and browser-based mobile sign-in.
3. Deploy Flow Web with its updated cookie request protections and shared rate limiter.
4. Build and release Flow Mobile with the new browser sign-in fallback before encouraging users to enable MFA. Older mobile versions may fail sign-in when Identity returns `mfa_required`.
5. Perform functional authentication, authorization and native-device checks before general rollout. Static checks do not establish runtime compatibility.

## Required configuration

- Use HTTPS in production. Identity `APP_URL` determines the passkey origin and relying-party hostname. Choose a stable domain before enrolling passkeys; changing it can make existing credentials unusable.
- Keep `ENCRYPTION_KEY` stable, private and backed up. Rotating it without migrating encrypted authenticator secrets breaks existing TOTP enrollment.
- Supply strong, distinct Identity session/encryption secrets and a strong Flow `AUTH_SECRET`. Flow and the realtime service must agree on `REALTIME_JWT_SECRET`. No live secrets were rotated by this change.
- Set `EMAIL_PROVIDER=smtp` in production and provide SMTP configuration.
- Ensure MongoDB can create the unique and TTL indexes used by MFA challenges, passkeys, mobile sign-in requests and shared rate counters. Confirm indexes exist during deployment.
- Configure `TRUSTED_CLIENT_IP_HEADER` for your ingress. It defaults to `x-forwarded-for`, using the rightmost address. The trusted proxy must strip or replace client-supplied forwarding headers; otherwise IP limits are not reliable. Per-account limits also apply.
- Development seeding requires `NODE_ENV=development`, `ALLOW_DEVELOPMENT_SEED=true` and a supplied `DEV_SEED_PASSWORD` of at least 16 characters. The known `dev@noirly.test` seed identity is blocked in production. Review existing seed records separately; none were deleted from production.
- Android release builds require the configured release keystore. They no longer fall back to the default debug signing key.
- Refresh production assets and CDN caches when deploying source-map restrictions. Verify deployed assets separately; local configuration does not remove maps previously uploaded elsewhere.

## User-facing changes

- Identity account settings support authenticator setup, one-time recovery codes and passkey management. Authenticator setup provides a manual key and app link.
- A user-verified passkey completes MFA. Password and Google sign-in challenge users who have enrolled a factor.
- Security changes require a sign-in within five minutes and revoke other credentials. Existing Flow sessions may therefore require sign-in again.
- Flow Web Google sign-in goes through Identity's login flow.
- Flow Mobile supports system-browser sign-in for passkeys and authenticators. The user enters the six-digit code shown in the app into the browser approval page. The app keeps its polling secret in memory and stores resulting credentials in Keychain; access tokens are not placed in browser URLs.

## Coverage and limits

| Requested control | Implementation / limitation |
| --- | --- |
| MongoDB injection | Input schemas, string/ObjectId validation and controlled query construction; prior review files are preserved. |
| XSS | Nonce-based page CSP and SVG rendering in image context; no raw SVG injection into the document. |
| CSRF / CORS | Same-origin checks, cookie request tokens/headers, Google nonce binding and POST logout confirmation; native bearer requests retain their separate authentication path. |
| Upload validation | Flow now has task attachments. Multipart streams are bounded even without an accurate Content-Length; each file is capped at 25 MB. Inline MIME types require matching signatures or valid plain text; other content downloads as octet-stream with nosniff. Downloads require workspace permission. This is not malware scanning. |
| Object authorization / permissions | Workspace ownership checks for task relationships, member changes and invite consumption. Server-side checks remain essential for every new endpoint. |
| RLS | MongoDB does not provide PostgreSQL-style RLS. Application queries enforce tenant scope; no database RLS policy was created. |
| Rate limiting | Shared MongoDB counters on sensitive Identity actions and Flow API requests. Trusted ingress configuration is required. |
| Secrets / password storage | Production configuration checks, existing Argon2id password hashing and server-only secrets. Existing secrets were not rotated. |
| Token storage | Web sessions use HttpOnly cookies; native sessions use Keychain. |
| MFA | Authenticator codes, single-use recovery codes and user-verified passkeys. Enrollment remains optional. |
| Webhooks | Signature verification, required claims and maximum token age; deletion remains idempotent. No separate replay database was added. |
| SSRF | Exact configured logo sources, restricted URL handling and rejected redirects on relevant outbound requests. |
| Source maps | Disabled production browser maps and blocked map requests; deployed/CDN copies require operational review. |
| Defaults / logs | Guarded development seed, production seed-account blocking, mandatory Android release signing and reduced sensitive error/email logging. |
| Dependencies | Updated web dependencies and compatible mobile lockfile dependencies. Remaining advisories must be reviewed; do not force incompatible downgrades just to clear audit output. |

## Verification and remaining work

Verified locally on 12–13 October 2026:

- Identity: 140 tests passed, including MFA replay/recovery races, cryptographic passkey checks and mobile browser approval. The production build passed with disposable keys and isolated configuration. The login-form lint issue is fixed.
- Identity browser smoke: passkey enrollment, authenticator enrollment, standalone passkey sign-in while TOTP is enabled, and password sign-in with a recovery-code challenge passed using a virtual authenticator and a disposable database.
- Flow Web: 63 unit tests passed after adding binary upload bounds and MIME validation. The production build and all 15 selected security/authentication/attachment Playwright tests passed. The later full browser run finished with 59 passed and 4 failed: CSV export, chat updates across users, email invite acceptance and the already-a-member invite message. Those four scenarios remain unresolved. These runs used isolated accounts, a disposable database and local file storage.
- Flow Mobile: full dependency installation succeeded; 12 tests passed, including Keychain adapter regression tests. Removed the obsolete Keychain SECURITY_RULES option.
- Android: signed release APK and AAB built successfully for all configured architectures. APK signature verification and ZIP alignment passed; all 34 bundled 64-bit libraries in both artifacts passed 16 KB ELF segment alignment. Bundletool validation passed and the AAB specifies PAGE_ALIGNMENT_16K. These local artifacts have versionCode 1 and are not ready to upload over the previously reported versionCode 2; set a new unused higher code for the upload build. Release JavaScript/Hermes bundling passed with Metro 0.87.1.
- TypeScript checks passed for all three projects during verification. Identity changed-file lint passed. Flow's full lint now passes after fixing state synchronization in the theme controls, command palette, task drawer and realtime status, plus remaining ref/unused-variable findings. Generated build and browser-report files are excluded from lint.
- Local realtime integration passed with Flow's actual JWT signer and an isolated WebSocket server: permitted subscription/event delivery succeeded and another project's subscription was rejected. Identity SMTP connection/authentication verification passed without sending mail. Live-service checks stopped at the user's request; no Vercel configuration was changed. See [Vercel configuration](VERCEL-CONFIGURATION.md) for missing local settings and deployment limits.

The latest full audits report 5 high findings in each web project and 51 high findings in mobile, all propagated from the same unpatched [braces advisory](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm). There are no remaining critical or moderate findings in those audits. Production-only web audits reported zero findings. Metro's vulnerable image parser and the old coverage-tool YAML dependency were removed through tested overrides; no incompatible framework downgrade was applied. The earlier private-registry install failure did not recur on the full-install retry.

Still pending: four Flow browser scenarios above, an upload build with a new version code, app runtime testing on 16 KB Android, real-device biometric/browser-return behavior and live Google OAuth/email delivery/R2/realtime integration. A dedicated emulator was created and confirmed PAGE_SIZE=16384, but the app was not installed or exercised on it. iOS is excluded by request. No production deployment, secret rotation or production database mutation was performed. Local alignment checks do not retroactively fix Play Console's previously uploaded version code 2.
