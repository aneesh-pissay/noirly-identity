# Validating Noirly Identity tokens

Every token Identity signs is a JWT signed with **RS256** by a key in `/.well-known/jwks.json`. They differ in who they're for and what their header `typ` says, and you must check both, or one kind can be passed off as another.

| Token | Who checks it | Header `typ` | `aud` |
| --- | --- | --- | --- |
| ID token | Your app, after the code exchange or a refresh | `JWT` | Your `client_id` |
| JWT access token (asked for with `resource=`) | The API it's for | `at+jwt` | The API's registered identifier |
| Back-channel logout token | Your app's `backchannelLogoutUri` | `logout+jwt` | Your `client_id` |
| Account deleted / merged notice | Your webhook | `secevent+jwt` | Your `client_id` |

Opaque access tokens (no `resource=`) aren't JWTs. Use them at UserInfo, or check them with [introspection](INTEGRATION.md#introspection-for-apis).

[`examples/verify-tokens.ts`](examples/verify-tokens.ts) does every check below with [`jose`](https://github.com/panva/jose) and is safe to copy. [`tests/token-validation.test.ts`](../tests/token-validation.test.ts) runs it against real Identity tokens, including each failure listed here.

## Every token

1. **Keys come from JWKS**, cached, and refetched once when a token names a `kid` you haven't seen. Identity rotates keys: the next key is published days before it signs, and retired keys stay until their tokens expire. Never pin one key, and never refetch for every token. (`createRemoteJWKSet` does this for you.)
2. **The algorithm is RS256, and only RS256.** Pass an allow-list. Reject `alg: none`. Reject HS256 too: a verifier that lets the token choose its algorithm can be tricked into using Identity's public key as an HMAC secret.
3. **The signature verifies** against the key whose `kid` the header names.
4. **`typ` is the one you expect** (see the table). This is what keeps a logout token or an API token from passing as an ID token.
5. **`iss` equals the issuer exactly** as discovery gives it (no trailing slash).
6. **`aud` is you**: your `client_id`, or your API's identifier.
7. **`exp` hasn't passed and `iat` isn't in the future**, allowing a minute of clock skew and no more.

## ID tokens

8. **`nonce` matches** the value you generated for this sign-in and stored (in the session, or a short-lived cookie). Reject a missing or different `nonce`: that's a replayed or injected token.
9. **`sub` is the account.** Key your users on `sub` (with `iss`), never on email: emails change, and accounts can be merged.
10. **`auth_time`**: if you sent `max_age`, check `now - auth_time <= max_age`. The token proves what happened; your request only asked for it.
11. **`acr` / `amr`**: if you asked for a level (`acr_values`, or `acr` in `claims`), check `acr` is one you accept (`urn:noirly:acr:mfa` for a second step). Identity answers `unmet_authentication_requirements` rather than issuing a weaker token, but check anyway.
12. **`sid`** identifies the Identity session. Store it with your session so back-channel logout can find it.
13. If `aud` were ever a list, `azp` must be you. Identity always issues a single audience.

## JWT access tokens (at your API)

8. **`aud` is your API's identifier**, not your `client_id`. A token for another API must not work at yours.
9. **`scope` covers the request**: `crm.write` for a write, and so on. Scopes are space-separated.
10. **`client_id`** says which app is calling, if your API treats apps differently.
11. **They can't be recalled before `exp`.** That's why they last 15 minutes by default. If a sign-out must take effect at once, introspect as well (or instead): introspection answers `active: false` as soon as the session ends.

## Back-channel logout tokens

8. **`events` contains `http://schemas.openid.net/event/backchannel-logout`.**
9. **There's no `nonce`.** If there is one, it's an ID token being replayed at your logout endpoint.
10. **`jti` is new.** Remember each `jti` for a few minutes and refuse repeats.
11. **End the session named by `sid`.** With no `sid`, end every session of `sub`. Then answer `200`.

## Failures

Reject any token that fails any check, without detail to the caller. Log the reason on your side. In your app, a rejected ID token means sending the person to sign in again. At your API, it means `401` with `WWW-Authenticate: Bearer error="invalid_token"`. A token with the wrong scope means `403` with `error="insufficient_scope"`.

| What's wrong | Check that catches it |
| --- | --- |
| Token for another app or API | `aud` |
| Token from another provider, or a test issuer | `iss` |
| Expired, or signed in the future | `exp`, `iat` |
| Replayed or injected ID token | `nonce` |
| `alg: none`, or HS256 keyed with the public key | algorithm allow-list |
| Changed payload | signature |
| Signed by a key Identity never published, or one it dropped after a leak | JWKS lookup by `kid` |
| API token used as an ID token, or the reverse; logout token used as either | `typ` |
| Sign-in too old, or too weak | `auth_time` with `max_age`, `acr` |
| Logout token replayed | `jti` |
| Access token without the needed scope | `scope` |
