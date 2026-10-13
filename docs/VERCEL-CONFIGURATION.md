# Vercel configuration for Noirly Identity and Flow

Checked against the local code on 13 October 2026. The Vercel dashboard was not accessed or changed. A missing local variable does not prove it is missing in Vercel.

## Missing locally

| Feature | Project | Missing configuration |
| --- | --- | --- |
| Google sign-in | Identity | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` |
| Invitation email | Flow | `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, `EMAIL_FROM` (host/user/password are absent locally) |
| Private attachments | Flow | `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_BUCKET_NAME` |
| Live authentication/realtime integration | Flow | Configured local Identity and realtime addresses refused connections. Production needs reachable HTTPS/WSS endpoints. |

Identity's existing SMTP credentials passed connection/authentication verification; no email was sent. No live-service checks were continued after the request to only report configuration.

## Identity Vercel project

Use the actual production domains if they differ from these repository examples.

| Variable | Value / source |
| --- | --- |
| `MONGODB_URI` | MongoDB connection string ending in the Identity database name. |
| `APP_URL`, `OIDC_ISSUER` | `https://noirly.identity.aneesh-pissay.in` |
| `SESSION_SECRET` | A strong random server secret, distinct from all other secrets. |
| `ENCRYPTION_KEY` | Preserve the existing key used to encrypt enrolled authenticator secrets. Back it up; do not replace it casually. |
| `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY`, `JWT_KEY_ID` | Existing matching RS256 signing keys and key ID. PEM newlines may be literal or escaped as `\n`. |
| `EMAIL_PROVIDER` | `smtp` |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE` | Mail provider configuration; typically `587`/`false` for STARTTLS or `465`/`true` for implicit TLS. |
| `SMTP_USER`, `SMTP_PASS`, `EMAIL_FROM` | Provider credentials and an authorized sender. |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | Google Cloud web OAuth client credentials. |
| `GOOGLE_MOBILE_CLIENT_IDS` | Optional comma-separated additional accepted Google token audiences, when required by the native client configuration. |
| `TRUSTED_CLIENT_IP_HEADER` | `x-vercel-forwarded-for` on Vercel; review if another proxy sits in front. |
| `ACCOUNT_DELETION_WEBHOOKS` | `noirly-flow=https://noirly.flow.aneesh-pissay.in/api/identity/account-deleted` if the registered Flow client ID is `noirly-flow`. |

Google Cloud must allow the Identity JavaScript origin and the exact callback URL `https://noirly.identity.aneesh-pissay.in/api/auth/google/callback`. Google OAuth client configuration is done in Google Cloud, not Vercel. Native Google sign-in also requires the Android application/package and signing-certificate configuration for the released app.

Passkeys and authenticator MFA do not require a paid MFA provider or a new MFA-specific environment variable. They use the stable HTTPS Identity origin, MongoDB and `ENCRYPTION_KEY`.

## Flow Vercel project

| Variable | Value / source |
| --- | --- |
| `MONGODB_URI` | MongoDB connection string ending in the Flow database name. |
| `AUTH_URL`, `NEXT_PUBLIC_APP_URL` | `https://noirly.flow.aneesh-pissay.in` |
| `AUTH_SECRET` | Strong random secret unique to Flow. |
| `AUTH_NOIRLY_ISSUER`, `NEXT_PUBLIC_IDENTITY_URL` | `https://noirly.identity.aneesh-pissay.in` |
| `AUTH_NOIRLY_CLIENT_ID`, `AUTH_NOIRLY_CLIENT_SECRET` | Credentials of a production OIDC client registered in Identity. These are not Google credentials. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, `EMAIL_FROM` | Mail provider settings for Flow invitations; Identity's Vercel variables are not automatically shared with Flow. |
| `CRON_SECRET` | Random server secret of at least 32 characters for the mention and task email workers. Initial assignment/mention delivery runs after the response. `vercel.json` schedules mention retries daily and overdue task reminders at 03:30 UTC (9 AM India time), beginning the day after the due date. Both use Flow SMTP. |
| `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_BUCKET_NAME` | Cloudflare R2 account, scoped S3 API credentials and private bucket. |
| `REALTIME_INTERNAL_URL` | Reachable HTTPS base URL of the realtime backend. Do not use localhost. |
| `NEXT_PUBLIC_REALTIME_WS_URL` | Public WSS endpoint, for example `wss://your-realtime-domain/ws`. |
| `REALTIME_JWT_SECRET` | Same strong JWT secret configured on the realtime backend. |
| `REALTIME_INTERNAL_SECRET` | Same internal-publish secret configured on the realtime backend; use a distinct secret from the JWT key. |
| `REALTIME_JWT_ISSUER`, `REALTIME_JWT_AUDIENCE` | `noirly-flow` and `noirly-realtime`, matching the backend. |
| `TRUSTED_CLIENT_IP_HEADER` | `x-vercel-forwarded-for` on Vercel. |

Register the Flow OIDC callback in Identity as `https://noirly.flow.aneesh-pissay.in/api/auth/callback/noirly`. Register its post-logout redirect as needed. Do not run the development seed against production to provision this client.

## Limits that environment variables do not solve

- **25 MB attachments:** the current implementation proxies uploads/downloads through Flow's API. Vercel documents a 4.5 MB function request/response payload limit. Adding R2 variables does not bypass that limit. Full-size support needs authorized short-lived direct-to-R2 uploads/downloads, with server-side permission checks and post-upload size/content validation, or a backend that supports the payload size. Do not expose the bucket publicly to work around it. [Vercel function limits](https://vercel.com/docs/functions/limitations)
- **Realtime hosting:** Vercel now offers WebSockets in beta. The existing standalone realtime server is not configured as a Vercel function entry point; it needs deployment adaptation and external shared state (the repository includes Redis adapters), or separate hosting. Function-duration limits require reconnect/replay handling. Environment variables alone do not deploy it. [Vercel WebSockets](https://vercel.com/docs/functions/websockets)
- **Unpatched dependency:** the remaining `braces` advisory has no published patched version. Vercel settings cannot fix it. [Upstream advisory](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm)
- **Android release/device checks:** APK/AAB signing, Play Console upload and native-device verification happen outside Vercel.

## Applying configuration

In each Vercel project, open Settings → Environment Variables, choose Production (and separate Preview values if needed), save, then redeploy. Only the `NEXT_PUBLIC_*` values above belong in browser bundles. Keep OAuth secrets, database credentials, R2 secrets, signing keys and SMTP passwords server-side.

Do not set `NODE_ENV=development`, `ALLOW_DEVELOPMENT_SEED=true`, `INVITE_EMAIL_OUTBOX`, `MENTION_EMAIL_OUTBOX`, `TASK_EMAIL_OUTBOX`, `ATTACHMENTS_LOCAL_DIR`, or test-only secrets in production. Do not replace existing production secrets merely to fill out this table.

Sources: [Vercel environment variables](https://vercel.com/docs/environment-variables), [Vercel request headers](https://vercel.com/docs/headers/request-headers).
