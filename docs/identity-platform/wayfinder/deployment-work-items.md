# IAM deployment work items

Separate from the W-1…W-14 development proving milestone. These items turn the tested IAM service
into a runnable, private staging deployment and then into a production-operable service.

## DEP-1 — Package and configure a runnable IAM runtime

**Status.** Ready.
**Summary.** Add a container image, staging configuration, datasource and Flyway migration path, health/readiness checks, secret-backed capability wiring, and one seeded app registration so the executable jar can start outside tests.
**Depends on.** `W-9.`

## DEP-2 — Production outbox transport and relay scheduler

**Status.** Planned.
**Summary.** Implement the real `OutboxTransport`, schedule the relay with leases, publish and acknowledge safely, and expose retry/quarantine state. Test-only transport does not satisfy this.
**Depends on.** `W-9, DEP-1.`

## DEP-3 — Workload identity authentication for the snapshot

**Status.** Planned.
**Summary.** Implement mTLS or signed workload-JWT authentication for the internal onboarding snapshot, bind it to app registration and audience, and remove the test-only authenticator from the runtime path.
**Depends on.** `W-9, DEP-1.`

## DEP-4 — Real issuer, TLS and key custody

**Status.** Planned.
**Summary.** Replace the `.invalid` issuer with the real HTTPS issuer, terminate TLS, source signing/encryption/blind-index material from secret storage, and document rotation and fail-closed behaviour.
**Depends on.** `DEP-1.`

## DEP-5 — Deploy a private staging environment and smoke it

**Status.** Planned.
**Summary.** Run IAM and PostgreSQL in a private staging environment with synthetic data; prove discovery, authorization, token, DPoP, activation, snapshot and health paths end to end.
**Depends on.** `W-12, DEP-1, DEP-2, DEP-3, DEP-4.`

## DEP-6 — Production operational gates

**Status.** Planned.
**Summary.** Add backups/restore, alerts, SLOs, capacity evidence, migration rollback, incident runbook and release approval. This is the gate that may call the service production-ready.
**Depends on.** `W-14, DEP-5.`
