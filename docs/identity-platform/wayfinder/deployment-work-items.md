# IAM deployment work items

Separate from the W-1…W-14 development proving milestone. These items turn the tested IAM service
into a runnable, private staging deployment and then into a production-operable service.

## DEP-1 — Package and configure a runnable IAM runtime

Integrated in local commit `ed5effa`. See the central registry for verification and handoff.
**Summary.** Add a container image, staging configuration, datasource and Flyway migration path, health/readiness checks, secret-backed capability wiring, and one seeded app registration so the executable jar can start outside tests.
**Depends on.** `W-9.`
**Runbook.** [`deployment/local-runtime.md`](../deployment/local-runtime.md).

## DEP-2 — Production outbox transport and relay scheduler

**Status.** Green — pending independent review.
**Summary.** Implement the real `OutboxTransport`, schedule the relay with leases, publish and acknowledge safely, and expose retry/quarantine state. Test-only transport does not satisfy this.
**Depends on.** `W-9, DEP-1.`
**Evidence.** [`deployment/evidence/DEP-2.md`](../deployment/evidence/DEP-2.md).

## DEP-3 — Workload identity authentication for the snapshot

**Status.** Green — pending independent review.
**Summary.** Implement mTLS or signed workload-JWT authentication for the internal onboarding snapshot, bind it to app registration and audience, and remove the test-only authenticator from the runtime path.
**Depends on.** `W-9, DEP-1.`
**Profile.** [`deployment/workload-token-profile.md`](../deployment/workload-token-profile.md).
**Evidence.** [`deployment/evidence/DEP-3.md`](../deployment/evidence/DEP-3.md).

## DEP-4 — Real issuer, TLS and key custody

**Status.** Ready. IAM-side work can start; real-binding evidence is coordinated with the infra binding.
**Summary (IAM).** Consume the infra-provided issuer hostname, TLS endpoint and key references: validate and
pin the issuer authority, implement the KMS/secret-backed capability adapters, publish and retire JWKS
keys, document rotation and compromise handling, and keep startup fail-closed with no local fallback.
**Summary (infra).** Infra owns the exact DNS name and records, TLS termination and certificate renewal,
KMS/HSM or secret-manager provisioning, service-account policies and audit, secret injection, private
routes, and the mTLS decision. The provider-side handoff is `portfolio/INFRA-13`; the environment is
`portfolio/INFRA-8`.
**Depends on.** `DEP-1`; provider parity with `portfolio/INFRA-13`.

**IAM decisions (accepted 2026-11-09).**

- Key purposes are fixed: ES256 signing, AES-256-GCM identifier encryption, HMAC-SHA-256 blind index,
  HMAC-SHA-256 challenge digest, ES256 workload signing. No key is reused across purposes.
- Signing rotates every 90 days with a short overlap. Encryption and blind-index versions stay readable
  until the backfill completes; retired JWKS keys stay published until the longest token expires.
- Staging and production fail startup if a capability is missing, unhealthy, or points at a key that is
  not published. There is no local-key fallback.
- The issuer is accepted only from infra, must be HTTPS with no path or trailing slash, is stable per
  environment, and has one authority pin per environment. A change is a coordinated client re-pin.
- Human access tokens stay at or below 15 minutes with no refresh token; the native client requires DPoP.

Boundary decision: `capabilities/work/decisions/iam-issuer-tls-custody-boundary-001.yaml`.

## DEP-5 — Deploy a private staging environment and smoke it

**Status.** Ready once the registered dependencies are satisfied.
**Summary.** Run IAM and PostgreSQL in a private staging environment with synthetic data; prove discovery, authorization, token, DPoP, activation, snapshot and health paths end to end.
**Depends on.** `DEP-1, DEP-2, DEP-3, DEP-4, DEP-7`, `portfolio/INFRA-8` and `portfolio/INFRA-13`.

## DEP-6 — Production operational gates

**Status.** Ready once the registered dependencies are satisfied.
**Summary.** Add backups/restore, alerts, SLOs, capacity evidence, migration rollback, incident runbook and release approval. This is the gate that may call the service production-ready.
**Depends on.** `W-14, DEP-5.`

## DEP-7 — Prove approved native sign-in and environment registration

**Status.** Ready.

IAM owns an approved human sign-in path and independently validatable staging registration. Start by defining the public-client and resource-server contract with Dutch and the Host, including account lifecycle needed for the invite cohort.

**Profile decisions (accepted 2026-11-09).** Public native client, authorization code with S256 PKCE
through the external browser, exact registered redirect, one resource audience, DPoP proof-bound access
and DPoP-bound rotating refresh, no client secret, sign-out wipe, and refusal on stale or incompatible
credentials. Refresh families are scoped per identity/app/client/device with rotation and reuse
detection, and the token endpoint issues and rotates them
(`capabilities/work/decisions/iam-native-refresh-001.yaml`).

**Acceptance**

- Record issuer, client and redirect binding, resource, scope, nonce, PKCE, DPoP and required keys/limiter.
- Prove a real authenticated principal can complete authorization under a staging registration. Reject wrong app, audience, key, replay and missing proof.
