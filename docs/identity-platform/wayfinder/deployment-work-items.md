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

**Status.** Ready once the registered dependencies are satisfied.
**Summary.** Replace the `.invalid` issuer with the real HTTPS issuer, terminate TLS, source signing/encryption/blind-index material from secret storage, and document rotation and fail-closed behaviour.
**Depends on.** `DEP-1.`

## DEP-5 — Deploy a private staging environment and smoke it

**Status.** Ready once the registered dependencies are satisfied.
**Summary.** Run IAM and PostgreSQL in a private staging environment with synthetic data; prove discovery, authorization, token, DPoP, activation, snapshot and health paths end to end.
**Depends on.** `DEP-1, DEP-2, DEP-3, DEP-4, DEP-7` and `portfolio/INFRA-8`.

## DEP-6 — Production operational gates

**Status.** Ready once the registered dependencies are satisfied.
**Summary.** Add backups/restore, alerts, SLOs, capacity evidence, migration rollback, incident runbook and release approval. This is the gate that may call the service production-ready.
**Depends on.** `W-14, DEP-5.`

## DEP-7 — Prove approved native sign-in and environment registration

**Status.** Ready.

IAM owns an approved human sign-in path and independently validatable staging registration. Start by defining the public-client and resource-server contract with Dutch and the Host, including account lifecycle needed for the invite cohort.

**Acceptance**

- Record issuer, client and redirect binding, resource, scope, nonce, PKCE, DPoP and required keys/limiter.
- Prove a real authenticated principal can complete authorization under a staging registration. Reject wrong app, audience, key, replay and missing proof.
