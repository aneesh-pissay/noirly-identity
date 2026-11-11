# OpenID conformance testing

How to run the [OpenID Foundation conformance suite](https://openid.net/certification/about-conformance-suite/) against Noirly Identity, and what to expect. The suite drives Identity like a real app would, so it needs an Identity it can reach over HTTPS, and someone to sign in when it asks.

## Plans to run

All with **server metadata: discovery**, **client registration: static client**, **client authentication: client_secret_basic**, **response type: code**.

| Plan | Covers |
| --- | --- |
| `oidcc-basic-certification-test-plan` | Basic OP: code flow, ID token, UserInfo, `prompt`, `max_age`, `nonce`, `claims`, refresh, code reuse |
| `oidcc-config-certification-test-plan` | Config OP: discovery and JWKS |
| `oidcc-rp-initiated-logout-certification-test-plan` | RP-initiated logout (`end_session_endpoint`) |
| `oidcc-backchannel-rp-initiated-logout-certification-test-plan` | Back-channel logout |

## 1. An Identity the suite can reach

- **Hosted suite** (`https://www.certification.openid.net`, sign in with a Google or GitLab account): point it at a deployed Identity, such as a staging deployment with its own database. Not production: the setup adds clients and an account.
- **Local suite**: the suite's [docker-compose](https://gitlab.com/openid/conformance-suite) on this machine (it needs Docker), at `https://localhost.emobix.co.uk:8443`. Identity has to be reachable from its containers over HTTPS. Run `next dev --experimental-https` and use an issuer the containers can resolve (`https://host.docker.internal:3000`), with `OIDC_ISSUER` and `APP_URL` set to it.

## 2. Clients and a test account

Against that Identity's database (its `MONGODB_URI` in `.env.local`):

```bash
npm run conformance:setup -- --alias=noirly --confirm
```

`--suite=` defaults to the hosted suite; pass the local one's address for a local run. This:

- registers `conformance-1` and `conformance-2` as confidential clients at the suite's addresses for that alias (callback, post-logout redirect, back- and front-channel logout), with PKCE optional (the basic plans don't send it) and no consent screen;
- creates or resets `conformance@noirly.test` with a fresh password;
- writes `.conformance/<alias>.json` (the suite config, with client secrets) and `.conformance/<alias>.account.json` (the account). Both are git-ignored. Don't share them.

`--confirm` is needed for anything but localhost.

## 3. Run

In the suite: **Create a new test plan**, pick the plan and the variants above, paste `.conformance/<alias>.json` into the JSON tab, and start. Run each test. When a test says to visit Identity, sign in as the test account. Where the suite asks for a screenshot (error pages, the logout confirmation), upload one from the browser.

## 4. Clean up

```bash
npm run conformance:setup -- --remove
```

## What to expect

These are deliberate, and pass or leave a warning the suite accepts:

- **Request objects** (`request`, `request_uri`): not supported. Identity answers `request_not_supported` / `request_uri_not_supported` on the redirect URI, and discovery says so.
- **Invalid `redirect_uri` or unknown client**: Identity shows an error instead of redirecting (no open redirects). The suite asks for a screenshot.
- **`prompt=login`**, **`max_age=1`**: sends the person to sign in again; `auth_time` moves.
- **`prompt=none`** without a session: `login_required` on the redirect URI.
- **`id_token_hint`** for a different account than the signed-in one: the account picker, or `login_required` with `prompt=none`.
- **Logout**: `end_session_endpoint` shows a confirmation page; sign out there. `post_logout_redirect_uri` works with `client_id` or with `id_token_hint` alone.
- **`state`** is required (OIDC only recommends it), as a CSRF safeguard for apps without PKCE. The suite always sends it; a request without it gets an error page.
- **UserInfo** takes the token in the `Authorization` header, or as `access_token` in a POST form body; never in the query.

Record each plan's result (the suite's export or its URL) next to the run date in [ROADMAP.md](ROADMAP.md) when Phase 5's last item is ticked.
