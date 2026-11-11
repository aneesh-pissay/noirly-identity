# Policies

Each policy names what Identity enforces in code, so it can't drift from practice. Owners review this file once a year and after any security incident.

## Access control

- Every account signs in with a password checked against known breaches, a passkey, or a linked provider; a second step (authenticator app or passkey) is required for admins and for spaces whose security settings demand it.
- Admin access is the `admin` role, granted only with `scripts/promote-admin.ts` by someone with database access; every admin action is recorded in the admin audit stream.
- Apps get only the scopes they're allowed; the claim review (`/admin/claims`) removes scopes no one has granted. Permissions follow default-deny roles (`lib/authz`), with time-limited elevation that needs approval.
- Sessions follow the strictest policy of the spaces someone belongs to (idle and absolute timeouts); sensitive actions need a recent sign-in.

## Audit logging

- Sign-ins, account changes and admin actions go to hash-chained, append-only streams (`lib/audit`); tampering breaks the chain and shows in the evidence.
- Retention is set by admins, never below 90 days; purges leave a checkpoint so the remaining chain still verifies.
- Chosen events alert by email (`/admin/audit` → Alerts). At least one alert rule must exist.

## Data protection and privacy

- People see what Identity holds about them, and why, on their privacy page; they can download it, with every Noirly app's data, and remove any app's access.
- Secrets (passwords, keys, recovery codes) are stored hashed or sealed with `ENCRYPTION_KEY`; signing keys are sealed and bound to their key id.
- Closing an account waits 14 days (undoable), then deletes it and tells every app, retrying until each confirms; admins see confirmations for 90 days.
- Data is kept as listed on the privacy page; sign-in history for one year.

## Key management

- One active signing key, rotated at least every 180 days (`npm run keys:rotate` or the scheduled rotation); the next key is published before use and retired keys stay published until every token they signed has expired.
- `ENCRYPTION_KEY` and database credentials live only in the hosting provider's secret store.

## Incident response

1. Contain: lock the account (`/admin/security`), which signs it out everywhere and revokes its tokens; rotate the signing key if a key is suspected.
2. Investigate with the audit search and the account's chain; verify chains with the evidence.
3. Tell affected people (security alert emails go automatically for sign-ins and changes) and the apps involved.
4. Record what happened and what changed, and review this file.

## Account recovery

- Recovery waits 24 hours (72 without a recovery method), the owner is emailed and can cancel; risky recoveries go to an admin review queue.
