# Controls

Each control: what it is, where it's implemented, and the evidence. "Evidence" keys are fields of `npm run compliance:evidence` / `GET /api/admin/evidence`.

| # | Control | Implementation | Evidence |
|---|---------|----------------|----------|
| AC-1 | Admins use a second step | `lib/security`, `lib/auth`; spaces can require it (`lib/spaces/org-security.ts`) | `secondStep.ok`, `secondStep.adminsWithout` (must be empty) |
| AC-2 | Least privilege for apps | Allowed scopes per client; claim review (`lib/oauth/claim-review.ts`, `/admin/claims`) | Claim review shows no unused scopes; `client.updated` events with `removedScopes` |
| AC-3 | Default-deny authorization | `lib/authz/engine.ts`, `explain()` | Tests `tests/authz-*.test.ts`; `/api/authz/check` |
| AC-4 | Privileged access is time-limited and approved | `lib/authz/elevation.ts`, swept by the scheduled job | `authz.elevation_*` events in the admin stream |
| AC-5 | Compromised accounts can be contained at once | `lib/security/containment.ts`, `/admin/security` | `lockedAccounts.count`; `account.contained` events |
| AU-1 | Security events are logged, tamper-evident | `lib/audit/event-log.ts`, `lib/audit/chain.ts` | `auditChains.ok` with every stream checked |
| AU-2 | Logs are retained at least 90 days | `lib/audit/retention.ts` | `retention.ok`, `retention.accountDays`, `retention.adminDays` |
| AU-3 | Chosen events alert someone | `lib/audit/alert-rules.ts` | `alertRules.ok`, `alertRules.enabled` |
| AU-4 | Logs can be exported for review | `GET /api/admin/audit?export=…` | `audit.exported` events |
| CR-1 | Signing keys rotate | `lib/oidc/keys.ts`, `scripts/rotate-signing-keys.ts` | `signingKeys.ok`, `signingKeys.active.ageDays` ≤ `maxAgeDays` |
| CR-2 | Secrets are sealed or hashed | `lib/security/encryption.ts`, argon2 passwords | Code review; tests `tests/secret-rotation.test.ts` |
| IA-1 | Breached passwords are refused | `lib/security/breached-passwords.ts` | Tests `tests/breached-passwords.test.ts` |
| IA-2 | Risky sign-ins need more proof | `lib/security/risk.ts` | `auth.unusual_sign_in` events |
| IA-3 | Recovery waits and can be cancelled | `lib/account/recovery-methods.ts`, factor recovery | `recoveries.pending` |
| PR-1 | People can see and export their data | `lib/account/privacy.ts`, `lib/account/data-export.ts` | `account.data_exported` events |
| PR-2 | Deletion reaches every app | `lib/account/deletion-webhooks.ts`, `/admin/deletions` | `deletionNotices.ok` (no app gave up), `deletionNotices.pending` |
| PR-3 | Consent can be withdrawn per app | `lib/account/app-access.ts` | `oauth.access_removed` events |
| SC-1 | Sessions end on schedule and on demand | `lib/sessions`, session policies | `sessions.active`; tests `tests/sessions.test.ts`, `tests/session-lifetime.test.ts` |
| SC-2 | Apps are told when sessions end | `lib/oidc/backchannel-logout.ts` | Logout notice retries in the scheduled job's output |

A failing check is an incident for the control's owner: fix the cause, then collect the evidence again and keep both runs.
