# Compliance pack

What a reviewer (SOC 2, ISO 27001, a customer's security questionnaire) needs from Noirly Identity:

- [POLICIES.md](POLICIES.md): the policies Identity enforces, and where each is enforced.
- [CONTROLS.md](CONTROLS.md): the controls list, each with how it's implemented and the evidence that it holds.
- **Live evidence:** `npm run compliance:evidence` (prints JSON; exits 1 if any check fails, so it can run on a schedule), or `GET /api/admin/evidence?download=1` as an admin. Collecting it is itself recorded in the admin audit stream.

The evidence holds counts and ids only, never names or addresses, so it can be shared with an auditor as is.

For a review period, hand over:

1. The evidence JSON, collected at the start and end of the period (and from the scheduled run's history).
2. The admin audit export for the period: `/admin/audit` → Export, or `GET /api/admin/audit?export=admin&from=…&to=…`.
3. These documents, with [SECURITY.md](../SECURITY.md) and the key rotation runbook in `scripts/rotate-signing-keys.ts`.
