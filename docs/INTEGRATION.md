## Google sign-in (hosted by Identity)

Applications such as Noirly Flow should **not** integrate Google directly.

Instead:

1. Configure `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` on Identity
2. Set Google redirect URI to `{APP_URL}/api/auth/google/callback`
3. In the product app, show a **Noirly Login** button that starts OIDC against Identity
4. On Identity login, users can choose **Continue with Google**

This keeps one Noirly account across the ecosystem.

# Integrating with Noirly Identity

This guide shows how a future Noirly application (for example **NoirlyCRM** or **NoirlyFlow**) authenticates users through Noirly Identity using OAuth 2.0 Authorization Code + PKCE and OpenID Connect.

## 1. Register an OAuth client

Clients are stored in MongoDB (`OAuthClient`). The production way is the **admin generator** in Identity:

1. Sign in to Identity as an admin
2. Open `/clients` (also linked from Account)
3. Enter the app name, client id (`noirly-ledger`, `noirly-pulse`, …), and one origin per line (localhost + production)
4. Copy the printed `AUTH_NOIRLY_*` values into that app’s env and redeploy

Re-running the generator for an existing client **adds origins** and does not rotate the secret.

**Rotating a secret without downtime:** **Rotate secret** issues a new one and keeps the old one working for 24 hours. Deploy the new secret, check on `/clients` that the old one is no longer being used ("last used"), then **Retire old secret** (or let it lapse). **Secret leaked** replaces it at once: the old secret stops working immediately, and the app's own client credentials tokens are revoked, so the app can't sign anyone in until it has the new secret.

CLI remains available for local/automation:

```bash
npm run db:seed
```

Example seeded confidential client:

```text
name: NoirlyCRM
client_id: noirly-crm
client_secret: <printed once by seed>
redirect_uri: http://localhost:3001/api/auth/callback/noirly
post_logout_redirect_uri: http://localhost:3001/
```

### Development, staging and production

Each environment of an app is its own client: `noirly-crm` (production), `noirly-crm-staging`, `noirly-crm-dev`, each with its own secret, redirect URIs, origins and logout URIs. Add one with **Add environment** on `/clients` (or `POST /api/admin/clients/:clientId/environments`). Settings like scopes, PKCE, consent and a required second step are copied from the app; secrets, logout URIs and API grants aren't. Nothing crosses over: a token, a consent or an API grant for one environment means nothing to another.

Once an environment is set, its redirects are held to it: production and staging redirect only to `https` on real hosts; development only to local ones (`localhost`, `127.0.0.1`, `*.localhost`, `*.test`). Native app schemes (`noirlyflow://oauth`) are fine in any. People see `Noirly CRM (Staging)` or `(Development)` on the consent screen and in their account outside production.

Clients from before keep working as they were, local and live redirects together, until an environment is chosen for them; move their localhost redirects to a development environment first.

### Client types

| Type | Secret | PKCE |
| --- | --- | --- |
| `confidential` (server apps) | Required (Argon2id hashed at rest) | Recommended / required if `requirePkce=true` |
| `public` (SPAs/native) | None | Required |

### Redirect URIs

- Must be registered exactly (scheme, host, port, path, no arbitrary URLs)
- Authorization `redirect_uri` must match one registered value character-for-character
- Logout `post_logout_redirect_uri` must be in `postLogoutRedirectUris`

### Scopes

Initial scopes:

- `openid` (required)
- `profile`
- `email`

Prepared for later:

- `offline_access` (refresh tokens)
- `roles`
- `organizations`

A client may only request scopes listed in its `allowedScopes`.

## 2. Discovery

```http
GET /.well-known/openid-configuration
```

Use `issuer`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`, and `end_session_endpoint` from the document. Prefer discovery over hard-coding paths.

The document lists what Identity really does, kept in step by tests: endpoints (including `revocation_endpoint`, `introspection_endpoint` and the Noirly-specific `noirly_session_check_endpoint`), scopes, claims, `prompt` and `display` values, `acr` values, PKCE methods, client authentication methods per endpoint, and logout support.

Authorization responses carry `iss` ([RFC 9207](https://www.rfc-editor.org/rfc/rfc9207)), on codes and errors alike (`authorization_response_iss_parameter_supported`). If your app talks to more than one provider, check it equals the issuer you sent the person to before redeeming the code.

JWKS:

```http
GET /.well-known/jwks.json
```

Public keys only. ID tokens are signed with **RS256**.

Identity rotates its signing keys: JWKS holds the key signing now, the next one (published days before it signs anything), and retired ones until their tokens expire. Pick the key by the token's `kid`; cache JWKS (it's served with `max-age=3600`), and when a token's `kid` isn't in your copy, fetch JWKS again once before rejecting it. Most JWT libraries do this for you (`createRemoteJWKSet` in jose). Never pin a single key.

## 3. Authorization request

Generate:

- `state` (CSRF protection for the redirect)
- `nonce` (bound into the ID token)
- PKCE `code_verifier` + `code_challenge` (S256)

Example:

```http
GET /api/oauth/authorize
  ?client_id=noirly-crm
  &redirect_uri=http://localhost:3001/api/auth/callback/noirly
  &response_type=code
  &scope=openid%20profile%20email%20offline_access
  &state=random-state
  &nonce=random-nonce
  &code_challenge=BASE64URL(SHA256(code_verifier))
  &code_challenge_method=S256
```

Only `response_type=code` is supported (no implicit flow).

If the user is not signed in to Identity, they are redirected to `/login`. After login, consent is collected at `/consent` when the client requires it.

Successful redirect:

```text
http://localhost:3001/api/auth/callback/noirly?code=...&state=...
```

Validate `state` before exchanging the code.

## 4. Token exchange

```http
POST /api/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=AUTH_CODE
&redirect_uri=http://localhost:3001/api/auth/callback/noirly
&client_id=noirly-crm
&client_secret=CLIENT_SECRET
&code_verifier=CODE_VERIFIER
```

Confidential clients may also use HTTP Basic (`client_id:client_secret`).

Example response:

```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "...",
  "id_token": "...",
  "scope": "openid profile email offline_access"
}
```

### ID token claims

Validate with JWKS (the full checklist, with copyable code, is in [TOKEN-VALIDATION.md](TOKEN-VALIDATION.md)):

- `iss` = configured issuer
- `aud` = your `client_id`
- `sub` = stable user id (never treat email as the permanent subject)
- `exp` / `iat` / `auth_time`
- `nonce` matches the value you sent
- `sid` = the Identity session behind it; logout tokens name the same value (see Logout)
- profile/email claims according to granted scopes

The `profile` scope also carries the person's preferences, the same in the ID token and UserInfo:

| Claim | Meaning |
| --- | --- |
| `picture` | Profile photo URL (uploaded to Identity, or from Google). The URL changes when the photo does. |
| `locale` | BCP 47 language tag, such as `hi-IN`. Absent: use the device's language. |
| `zoneinfo` | IANA time zone, such as `Asia/Kolkata`. Absent: use the device's time zone. |
| `noirly_accessibility` | `{ motion: "system" \| "reduce", contrast: "system" \| "more", textSize: "default" \| "large" \| "larger" }`. `system` means follow the device's own setting. |

They're read at sign-in; refresh the ID token or call UserInfo to pick up later changes.

### Which claims you get

Claims follow the granted scopes, the same in the ID token and UserInfo: `email` brings `email` and `email_verified`; `profile` brings `name`, `given_name`, `family_name`, `picture` and the preference claims; `roles` brings `roles`. `sub`, `auth_time`, `sid`, `acr` and `amr` always come. Nothing else is released, however it's asked for.

The `claims` request parameter ([OpenID Connect Core §5.5](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter)) is supported, under the same rule:

- A claim asked for on its own (`{"userinfo":{"email":null}}`) becomes a request for its scope, so the consent screen and the grant cover it, and it arrives in both places like any scope's claims. It's only added when your app may be given that scope at all; otherwise it's quietly left out. Check the `scope` in the token response for what was granted.
- `{"id_token":{"acr":{"essential":true,"values":["urn:noirly:acr:mfa"]}}}` is a step-up, like `acr_values`. A non-essential `acr` is only a hint.
- `{"id_token":{"sub":{"value":"..."}}}` lets only that account answer: another signed-in account gets the account picker, or `login_required` with `prompt=none`.
- Unknown claims are ignored; malformed JSON comes back as `invalid_request` on your redirect URI.

`request` and `request_uri` (request objects) aren't supported.

### Organizations

Ask for the `organizations` scope to get an `organizations` claim: every organization (space) the person is in, with their role in each.

To open your app inside one organization, add `organization=<id or slug>` to the authorization request, or `organization=select` to let Identity show a picker. The tokens are then scoped to it: the ID token, UserInfo, JWT access tokens and introspection carry `org_id`, `org_slug` and `org_role`, and refreshes stay in it. Someone who isn't in that organization gets the picker (or `access_denied` with `prompt=none`); someone who leaves it can't refresh (`invalid_grant`), and introspection answers `active: false`. To switch organizations, run the authorization request again with `prompt=none` and the other organization. Keep each organization's data apart by `org_id`.

### Permissions (authorization)

Organizations define roles (sets of permissions like `invoice:read`, `invoice:*`, `*`) and give them to people, teams (sub-team members included) or service accounts, optionally only on some resources (`project/*`, `project/42`), under conditions (department, region, a trusted device, working hours, country) or until a time. Nothing is allowed unless a role grants it.

Your app gets them two ways, for a sign-in scoped to an organization (`organization=`):

- **Claims:** ask for the `permissions` scope. The ID token, UserInfo and JWT access tokens carry `permissions`: plain permissions (`invoice:read`) for roles on every resource, `invoice:read@ledger/*` for roles on some. Worked out when issued; refresh to pick up changes.
- **Live checks:** `POST /api/authz/check` with `Authorization: Bearer <access token>` and `{ "permission": "invoice:approve", "resource": "ledger/2026" }` answers `{ "allowed": true | false }`, conditions and expiries included. `GET /api/authz/permissions` lists everything allowed right now. Use these for anything sensitive.

**Service accounts** (an organization's own non-human accounts) get a token with the client credentials grant and no `resource`; it carries `org_id` and `permissions`, lasts 15 minutes, and works with the permissions API. They never sign people in.

### Step-up before a sensitive action

To make sure the person signed in recently, or with a second step, before something sensitive (deleting data, changing payouts), send them through authorize again with any of:

- `prompt=login`: sign in again, however recently they did.
- `max_age=<seconds>`: a sign-in no older than this; older sessions sign in again.
- `acr_values=urn:noirly:acr:mfa`: a second step. If the session lacks one, Identity asks for it (authenticator code, passkey or security key) and strengthens the same session, so the person stays signed in everywhere else. An account with no second step set up comes back with `error=unmet_authentication_requirements`.

With `prompt=none`, these answer `login_required` or `interaction_required` instead of showing anything. Then check the new ID token: `auth_time` (when they proved who they are), `acr` (`urn:noirly:acr:1fa` or `urn:noirly:acr:mfa`) and `amr` (RFC 8176 values: `pwd`, `otp`, `hwk`, `user`, `fed`, and `mfa` for two factors). A passkey that checked a PIN or fingerprint counts as `mfa` on its own.

### Requiring a second step

Rather than asking each time, a second step can be required:

- **For an app:** an admin sets `requireMfa: true` on its client (`PATCH /api/admin/clients/:clientId`). Every sign-in to it then reaches `acr` `urn:noirly:acr:mfa`; someone without a second step is sent to set one up, then on to the app.
- **For a space:** its admins tick "Require a second step at sign-in for every member". Its members then step up for every app, and can't remove their last second step. Members without one get seven days to set one up: an email when it starts, a nudge once per session on the way to an app, and after that apps are closed to them until they do. Spaces show `requireMfa` in the integration API.
- **For an account:** the person can require it of themselves, which keeps their last second step from being removed.

### Sign in with Apple in a native app

Get an id_token from Apple with the system sheet, passing the SHA-256 (hex) of a random nonce you keep. Then `POST /api/mobile/apple` with `{ client_id, id_token, apple_nonce: "<the raw nonce>", first_name?, last_name?, scope?, nonce? }` — Apple gives the name only on the first sign-in, so send it then. The answer is the same token response as `/api/mobile/google` (or `mfa_required`). Your app's bundle id must be in `APPLE_MOBILE_CLIENT_IDS`.

### Verifying an address in a native app

A new account's verification email carries a six-digit code as well as the link. A native app can let the person type it in instead of leaving the app: `POST /api/auth/verify-email/code` with `{ "email": "...", "code": "123456" }` returns `200 { status: "verified" }` (or `already_verified`), else `400 { status: "invalid" }`. Five wrong tries end that email's code. Then sign in as usual.

### Merged accounts

A person with two Noirly accounts can merge one into the other. The merged-away account is closed and its `sub` now belongs to the kept account. Apps listed in `ACCOUNT_MERGE_WEBHOOKS` get a Security Event Token like the deletion notice: `typ` `secevent+jwt`, signed with the JWKS keys, `aud` = your client id, `sub` = the old account, and `events["https://noirly.dev/events/account-merged"].new_sub` = the kept account. Move what you hold for `sub` to `new_sub` (merging where you already hold both), then answer 2xx; failures are retried. The spaces integration API answers for an old `sub` as the kept account.

## 5. UserInfo

```http
GET /api/oidc/userinfo
Authorization: Bearer ACCESS_TOKEN
```

Returns claims limited to the access token’s scopes.

## 6. Refresh tokens

Request `offline_access` to receive a refresh token.

```http
POST /api/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=REFRESH_TOKEN
&client_id=noirly-crm
&client_secret=CLIENT_SECRET
```

Security behavior:

- Refresh tokens are stored hashed
- Each use **rotates** the token
- Tokens are bound to user, client, and Identity session. When that session ends (sign-out anywhere, the device signed out from the account page, a password change, the session expiring), its refresh tokens end too: a refresh then fails with `invalid_grant`, and nothing new is minted
- Reuse of an old rotated token **revokes the entire token family everywhere**: every refresh token in it, every access token your app holds through that session, and your app's own session there (a back-channel logout token, see Logout). Identity and other apps stay signed in. Sign the person in again

## 7. Logout

```http
GET /api/oidc/logout
  ?client_id=noirly-crm
  &post_logout_redirect_uri=http://localhost:3001/
  &state=optional
```

Ends the Identity session and revokes associated access/refresh tokens for that session. Post-logout redirects are validated against the client allow-list.

### Who may use your app

An admin or the app's owner can limit an app to members of chosen spaces, or to a list of people. Someone outside it isn't signed in: they see Identity's "No access" page (with `prompt=none`, your redirect URI gets `error=access_denied`). It's checked again at every code exchange and refresh, so a refresh fails with `invalid_grant` once someone is taken out of the space or list.

### When someone removes your app

People can remove an app's access from their account page. Every token your app holds for them stops working at once (refresh fails with `invalid_grant`), your back-channel logout URI gets a logout token for their `sub` with no `sid` (end all their sessions), and the next sign-in shows the consent screen even if your app normally skips it. `prompt=none` answers `consent_required` until they agree again.

### When an account is deleted

List your app in `ACCOUNT_DELETION_WEBHOOKS` (`clientId=url`). When an account is deleted (or its 14-day closure ends), Identity POSTs a Security Event Token (`application/secevent+jwt`) to your URL: verify it with JWKS (`typ` = `secevent+jwt`, `iss`, `aud` = your `client_id`), and the `events` claim has `https://noirly.dev/events/account-deleted`. Delete your data for `sub` and answer 2xx. Failures are retried by the scheduled job; admins see which apps confirmed each deletion, for 90 days, at `/admin/deletions` (`GET /api/admin/deletions?state=pending|failed|confirmed`) and can retry one account at once (`POST` with `{ "sub": "…" }`).

### Lifecycle webhooks

To hear when people your app knows are created, changed, deactivated or deleted, or when their membership of a space changes, ask an admin to set `lifecycleWebhookUri` on your client (https), and optionally `lifecycleEvents` to choose (`PATCH /api/admin/clients/:clientId`). Events: `user.created`, `user.updated`, `user.deactivated`, `user.reactivated`, `user.deleted`, `membership.changed`.

You get an event for a person who has used your app, and for a space's events when the space lets members use your app. Each is a Security Event Token POSTed as `application/secevent+jwt`; verify it with JWKS like the others (`typ` = `secevent+jwt`, `iss`, `aud` = your `client_id`, `exp`):

```json
{
  "iss": "https://identity.example", "aud": "your-client-id", "sub": "<user id>",
  "txn": "<delivery id, the same on retries>",
  "events": { "https://noirly.dev/events/membership-changed": { "organizationId": "<space id>", "change": "deactivated" } }
}
```

The event URI is `https://noirly.dev/events/` plus the event name with `-` for `.` (`user-deactivated`). `membership.changed` says what changed in `change` (`joined`, `left`, `removed`, `role_changed` with `role`, `deactivated`, `reactivated`, `team_added` / `team_removed` with `teamId`, `groups_mapped`). Answer 2xx; anything else is retried with backoff for up to a week (10 tries), with the same `txn`, so drop a `txn` you've already handled. On `user.deactivated`, end the person's sessions and stop acting for them; on `user.deleted`, delete their data (as with the account-deleted notice).

### Personal data export

People can ask, from their privacy page, for one download with everything Noirly holds about them. To include your app's data, ask an admin to set `dataExportUri` on your client (`PATCH /api/admin/clients/:clientId`, https). Identity POSTs a Security Event Token (`application/secevent+jwt`) to it, verified like the deletion notice, with the event `https://noirly.dev/events/data-export-requested`. Answer `200` with that person's data as JSON (up to 5 MB), or `204` if you hold none. Failures are retried up to 5 times by the scheduled job; the bundle is ready once every app has answered or given up, and the person is emailed.

### Coordinated logout

When an Identity session ends (signed out here or from another app, signed out from the devices page, a password change or reset, the app signed out alone from the account page), every app that session signed in to is told, so it can end its own session too. Ask an Identity admin to set either URI on your client (`/clients` → Edit, or `PATCH /api/admin/clients/:clientId` with `backchannelLogoutUri` / `frontchannelLogoutUri`). Both must be https (http on localhost in development).

**Back-channel (preferred).** Identity POSTs `application/x-www-form-urlencoded` with one field, `logout_token`, to your `backchannelLogoutUri`, per [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html). Verify it like an ID token, with JWKS:

- header `typ` = `logout+jwt`, `alg` = `RS256`
- `iss` = the issuer, `aud` = your `client_id`, `iat` recent, `exp` (2 minutes), `jti` unique (reject repeats)
- `events` has the key `http://schemas.openid.net/event/backchannel-logout`
- no `nonce`
- `sid` present: end your session(s) whose ID token had that `sid`. `sid` absent: end every session of `sub` (sent when someone signs your app out on every device)

Answer `200` (any 2xx) once done. Anything else, or no answer within 3 seconds, is retried by the notice retry job (`scripts/retry-deletion-notices.ts`) for up to a day, and falls back to front-channel if the person is signing out in the browser right then.

**Front-channel (fallback).** When someone signs out in the browser, Identity loads your `frontchannelLogoutUri` in a hidden iframe with `iss` and `sid` query parameters, per [Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html), if you have no back-channel URI or its delivery just failed. Clear the session whose `sid` matches, and let Identity frame that page (`frame-ancestors` must allow the Identity origin; session cookies need `SameSite=None; Secure` to be sent in the frame). Identity waits up to 3 seconds for the frames.

Discovery advertises `backchannel_logout_supported`, `backchannel_logout_session_supported`, `frontchannel_logout_supported` and `frontchannel_logout_session_supported`.

### Silent sign-in across Noirly apps

Someone already signed in to Identity (say, through Noirly CRM) can be signed in to your app with no page at all. Send the normal authorization request with `prompt=none`, as a top-level redirect (not a hidden iframe: Identity can't be framed, and browsers block the cookies there anyway):

- Signed in: you get `code` back straight away. If your app needs consent, this works once the person has agreed to every scope you ask for; asking for more answers `consent_required`.
- Not signed in, or signed in too long ago for your `max_age`: `error=login_required`.
- Needs a page first (a second step, an unconfirmed address): `error=interaction_required`.

On any error, show your own "Sign in" button that sends the request without `prompt=none`.

### Checking the session is still going

`POST /api/oidc/session` (also `noirly_session_check_endpoint` in discovery) answers whether the Identity session behind a sign-in is still live. It's one lookup, cheap enough to poll every minute or on each page load, and asking never counts as activity, so it can't keep an idle session alive.

```http
POST /api/oidc/session
Authorization: Bearer ACCESS_TOKEN
```

or, from a confidential app's server, by the `sid` in its ID token:

```http
POST /api/oidc/session
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

sid=SID_FROM_ID_TOKEN
```

Answers `{ "active": false }`, or `{ "active": true, "sid": "...", "expires_at": 1767225600, "auth_time": 1767139200 }` (seconds; `expires_at` is the sooner of the session's end and its idle limit). By `sid`, only sessions that signed in to your app are answered for; any other looks inactive. Public apps use their access token. When it says inactive, end your session for that person. Back-channel logout tells you sooner; this catches what it can't, such as a session lapsing from its idle or overall time limit.

## 8. Token revocation

```http
POST /api/oauth/revoke
Content-Type: application/x-www-form-urlencoded

token=ACCESS_OR_REFRESH
&token_type_hint=refresh_token
&client_id=noirly-crm
&client_secret=CLIENT_SECRET
```

Revoking a refresh token revokes its whole family and the access tokens your app holds through the same session (RFC 7009: the grant, not just the token). With `client_id`, only tokens issued to that app are revoked. The answer is always `200`.

### Tokens for your API (resource indicators)

An API can take Identity access tokens it verifies itself, offline, with no call back to Identity. An admin registers it (on `/apis`, or `POST /api/admin/resources`) with an identifier (an absolute URI such as `https://api.crm.noirly.com`), the scopes it defines (say `crm.read`, `crm.write`, each with a description people see on the consent screen and in their account's app list), a token lifetime (default 15 minutes, at most an hour) and the apps that may ask for it.

The app names the API on the authorization request, with its scopes alongside the usual ones (`resource` may repeat):

```http
GET /api/oauth/authorize?...&scope=openid profile offline_access crm.read&resource=https://api.crm.noirly.com
```

then asks for a token for one of them at the token endpoint, on the code exchange or any later refresh:

```http
POST /api/oauth/token

grant_type=refresh_token&refresh_token=...&resource=https://api.crm.noirly.com
```

The `access_token` is then a JWT ([RFC 9068](https://www.rfc-editor.org/rfc/rfc9068)): header `typ` `at+jwt`, signed with the JWKS keys, `aud` = the API's identifier, `scope` = only that API's granted scopes, plus `sub`, `client_id`, `sid`, `auth_time`, `acr`, `amr`, `jti`. `scope` in the response describes it. The API checks the signature (by `kid`), `typ`, `iss`, `aud` = itself, `exp`, then `scope`. It won't work at Identity's own endpoints (UserInfo), and without `resource` you get the usual opaque token carrying only the OpenID Connect scopes.

A JWT can't be recalled before it expires, which is why the lifetime is short. An API that must notice a sign-out at once can introspect it as well (below); introspection answers `aud` for these. Unknown APIs, ones not open to your app, or ones not in the grant answer `invalid_target` (on authorize, back on your redirect URI; at the token endpoint, without using up the code or refresh token). One `resource` per token request.

### Machine-to-machine (client credentials)

A server-side job with no person behind it (a sync, a webhook worker) gets a token as itself with the client credentials grant. It must be a confidential app, and an admin must grant it machine access to the API: `machineGrants` on the API (`POST /api/admin/resources`), listing the app and which of the API's scopes it may have. Acting for people (`allowedClientIds`) doesn't include this.

```http
POST /api/oauth/token
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&resource=https://api.ledger.noirly.com&scope=ledger.read
```

`resource` is required: a machine token is for one API. Leave out `scope` for everything granted. The answer has an `access_token` (an `at+jwt` like the ones above, but with `sub` and `client_id` both the app, and no `sid` or `auth_time`), `expires_in` and `scope`. There's no refresh token or ID token; ask again when it runs out. An API can tell a machine token apart because `sub` equals `client_id`. Introspection answers `active: false` once the token expires or is revoked, the app is disabled, or its grant is withdrawn. Errors: `invalid_target` (no resource, or no grant for it), `invalid_scope` (beyond the grant), `unauthorized_client` (a public app).

### Introspection (for APIs)

Access tokens are opaque. An API that receives one checks it with [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) introspection, authenticating as a confidential client (register your API as one):

```http
POST /api/oauth/introspect
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

token=ACCESS_TOKEN&token_type_hint=access_token
```

Live: `{ "active": true, "token_type": "Bearer", "scope": "openid profile", "client_id": "noirly-crm", "sub": "...", "iss": "...", "iat": 1767139200, "exp": 1767142800, "sid": "...", "auth_time": 1767139100 }`. Anything else answers `{ "active": false }` without saying why: expired, revoked, its Identity session ended or went idle, or the account was disabled. `exp` is never later than the session behind the token. Check `scope` covers what the request does, and cache an answer no longer than until `exp` (a minute or so is safer, since sign-outs take effect at once).

Refresh tokens can be introspected only by the app they were issued to; any other app hears `active: false`. Public (mobile) clients can't introspect.

## 9. Error responses

OAuth errors use standard fields:

```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code expired"
}
```

Common codes: `invalid_request`, `invalid_client`, `invalid_grant`, `invalid_scope`, `access_denied`, `login_required`, `consent_required`.

Auth API errors:

```json
{
  "error": "invalid_credentials",
  "message": "Invalid email or password"
}
```

Login failures intentionally use generic messaging to reduce account enumeration.

## 10. Library recommendations

Any standards-compliant OIDC client works, for example:

- NextAuth / Auth.js (`Noirly` as OIDC provider)
- `openid-client`
- AppAuth (native browser redirect)

Configure:

- issuer = Identity `OIDC_ISSUER`
- client id/secret from registration
- scopes including `openid`
- PKCE enabled

## 11. Native mobile SDK (no WebView)

For React Native apps that need **native** email/password and Google UI (not a browser sheet), use `@noirly-dev/identity-mobile` against the mobile token APIs.

### Register a public client

```bash
npm run client:register -- \
  --type=public \
  --client-id=noirly-pulse-mobile \
  --name=NoirlyPulseMobile \
  --redirect-uri=noirly-pulse://oauth
```

Public clients have **no client secret**. Do not embed web client secrets in mobile binaries.

### Endpoints

| Method | Path | Body |
| --- | --- | --- |
| POST | `/api/mobile/login` | `{ client_id, email, password, scope? }` |
| POST | `/api/mobile/register` | `{ client_id, email, password, firstName, lastName, … }` |
| POST | `/api/mobile/google` | `{ client_id, id_token, nonce? }` |
| POST | `/api/mobile/refresh` | `{ client_id, refresh_token }` |
| POST | `/api/mobile/logout` | `{ client_id, refresh_token? }` |

All return JSON tokens:

```json
{
  "access_token": "…",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "…",
  "id_token": "…",
  "scope": "openid profile email offline_access",
  "user": { "id": "…", "email": "…", "displayName": "…" }
}
```

Google: use `@react-native-google-signin/google-signin` with Identity’s web client as `webClientId` (or list iOS/Android client IDs in `GOOGLE_MOBILE_CLIENT_IDS`), then POST the Google `idToken` to `/api/mobile/google`.

Refresh tokens rotate on every use; reuse of an old refresh token revokes the family. Mobile refresh also extends the backing session toward `REFRESH_TOKEN_TTL_SECONDS`.

### SDK usage

```ts
import { NoirlyIdentity } from "@noirly-dev/identity-mobile";

NoirlyIdentity.configure({
  issuer: "https://auth.noirly.com",
  clientId: "noirly-pulse-mobile",
});

await NoirlyIdentity.signInWithPassword({ email, password });
await NoirlyIdentity.signInWithGoogle({ idToken });
await NoirlyIdentity.getAccessToken();
await NoirlyIdentity.signOut();
```

Web apps (Pulse / Flow / Ledger) keep Auth.js + confidential clients. Mobile is a **separate public client** per product.

## Continue with Noirly

Product UX can offer **Continue with Noirly**, redirecting to:

```text
https://auth.noirly.com/api/oauth/authorize?...
```

Users keep one Noirly identity across the ecosystem; applications never store or manage Noirly passwords.

For **native mobile** (React Native, no WebView), see [§11 Native mobile SDK](#11-native-mobile-sdk-no-webview) and `@noirly-dev/identity-mobile`.
