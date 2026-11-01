Type: grilling
Status: resolved
Assignee: Codex
Parent: [Specify the shared first-party Identity Platform](../map.md)
Blocked by: 06, 08, 09, 11

# Design operations, resilience, abuse controls, and key management

## Question

What availability and recovery objectives, deployment topology, scaling limits, signing/encryption key custody and rotation, backup/restore, rate limits, abuse detection, observability, alerting, incident response, and cost controls make the shared login dependency operable?

## Decision

This ticket defines provider-neutral production requirements. Concrete cloud provider, region, compute, database service/topology, broker, cache, object storage, KMS/HSM product, network layout, and observability product are intentionally delegated to the separate cloud-solutions effort. That result must satisfy the acceptance constraints below and be reconciled into the final implementation handoff before infrastructure implementation.

### Deployment and isolation requirements

- Deploy IAM as one versioned modular application plus independently scalable outbox/maintenance worker modes only when needed. Run at least two application instances across independent failure domains in production; avoid Kubernetes, a service mesh, or self-managed stateful infrastructure unless the cloud design proves a requirement that managed containers cannot meet.
- Only the public authorization/security edge is internet reachable. Databases, worker administration, broker consumers, key-management paths, and administrative APIs use private networking and workload identity. Egress is allowlisted where practical.
- IAM owns an independently restorable production database and credentials. The cloud design must explicitly decide whether this is a dedicated physical managed database or a logically isolated database on shared infrastructure, document blast radius and cost, and define measurable extraction triggers. Cross-service schemas, roles, queries, replicas, backups, and transactions remain prohibited in either case.
- Development/test may share disposable infrastructure with separate databases and roles. Production identity, keys, identifiers, events, sessions, and backups never enter lower environments.
- Environments use different issuers, DNS, client IDs, redirect URIs, databases, encryption/signing keys, workload credentials, queues/topics, object stores, rate-limit namespaces, and administrative roles.

### Availability and recovery objectives

- The production target is at least 99.9% monthly availability for authorization, token, and authenticated security endpoints initially. Published SLOs distinguish login/authorization, refresh/token, JWKS/discovery, administrative, and asynchronous lifecycle delivery.
- Design target: no committed identity/security transaction is lost (`RPO` approaching zero through synchronous managed-database durability); disaster-recovery acceptance permits no more than five minutes of data loss only where the selected provider cannot economically guarantee zero. Target `RTO` is one hour for IAM authority and four hours for secondary administrative/export functions.
- A normal instance or failure-domain loss must recover automatically without operator data repair. Region-wide recovery may be runbook-driven initially; multi-region active-active issuance is out of scope until availability evidence justifies its consistency, key-custody, and cost burden.
- Discovery and JWKS are highly cacheable with safe overlap. Resource services continue local validation according to the settled outage policy; they do not silently weaken authorization when IAM is unavailable.
- Restore testing is mandatory at least quarterly and before irreversible schema/key retirement. Tests restore into an isolated environment, apply deletion tombstones/finalizers, validate migrations and cryptographic access, reconcile outbox/security versions, and record achieved RPO/RTO.

### Key custody and rotation

- Production issuer signing, identifier encryption/wrapping, blind-index HMAC, audit-integrity, export encryption, workload credentials, and general application secrets use separate purpose-bound keys and policies. One master secret is never reused across purposes or environments.
- Production private signing and root wrapping keys are generated and used through an approved managed key interface with non-exportability where supported. Runtime identity, not embedded credentials, authorizes signing/decryption operations.
- Services obtain only the operations they need: signing without key export, wrapping/unwrapping for the identifier vault, verification through public material, and no broad key-administrator permission.
- Rotation supports overlapping generations, explicit activation/retirement, rollback before retirement, published verification overlap through maximum token lifetime plus clock skew/cache margin, and resumable re-encryption/reindexing.
- Emergency compromise procedures disable issuance, activate a prepared key, preserve verification only when safe, revoke affected authority/security versions, notify owners, and produce an incident timeline. Key deletion is delayed until backup, audit, legal, and restore implications are resolved.
- Break-glass key administration is strongly authenticated, time-limited, alerted, reason/case-bound, and independently reviewed when staffing permits. Runtime services cannot change key policies.

### Abuse controls

- Apply layered controls by network source, protected identifier digest, Human Identity/App Subject where known, device/session, client, workload, credential, app, and operation sensitivity. Do not rely on IP alone or expose account existence through different limits/responses.
- Verification, OTP resend/check, authorization initiation, passkey failure, recovery, identifier change, refresh, token exchange, export, deletion, and administrative operations each have explicit burst, sustained, failure, and cooldown policies.
- Use progressive throttling, proof/challenge escalation where accessible, short cooldown, and reason-coded risk evaluation. Attackers must not be able to impose a permanent global lock through repeated guesses.
- Distributed counters/replay caches are non-authoritative and disposable. Durable challenge/token/session consumption and lock decisions remain in PostgreSQL. A cache outage follows an explicit conservative degraded policy and never makes unlimited attempts possible.
- DPoP replay IDs, authorization requests, nonces, and verification attempts have bounded retention and cardinality controls. Input/body/header sizes and expensive cryptographic work are bounded before deep processing.

### Observability and privacy

- Structured logs use an allowlist and include timestamp, service/version/environment, safe operation/event class, outcome/reason code, correlation/causation/trace IDs, latency, and opaque target class/reference only where approved.
- Logs, metrics, traces, profiler output, exception reports, dashboards, alerts, broker metadata, and support tickets exclude raw email/phone, credentials, authorization codes, OTPs, recovery evidence, cookies, assertions, access/refresh tokens, DPoP proofs, decrypted identifier values, request/response bodies, and cryptographic private material.
- Automated redaction and canary-secret/PII tests run in CI and staging. Access to production telemetry is least privilege, audited, retained by classification, and separated from key/database administration.
- Required metrics include authorization/token success and safe failure classes, latency/saturation, database pool/lock health, cryptographic dependency errors, refresh reuse, DPoP replay, challenge abuse, security-version projection lag, outbox oldest age/attempts, queue lag/DLQ, logout delivery, reconciliation gaps, key age/rotation, backup/restore evidence, and cost drivers.
- Alerts are actionable and routed by severity: issuance/signing failure, database unavailability, key access anomaly, compromise/reuse spikes, stale JWKS rotation, outbox/security projection lag, DLQ growth, restore failure, deletion-finalizer failure, and administrative/break-glass action.

### Incident response and changes

- Runbooks cover lost/stolen client credential, signing/encryption key compromise, identifier exposure, refresh-family attack, DPoP replay, malicious app/workload, database corruption/restore, event backlog, dependency/region outage, accidental deletion, and abusive operator access.
- Emergency controls can independently disable a client credential, client, app, resource, scope, workload, delegation workflow, factor type, identifier channel, signing generation, new authorization, refresh, or all issuance. Blast radius is explicit.
- Immutable images/artifacts are promoted through development and staging using the same digest. Infrastructure and policy are version controlled. Production mutation is reconciled and audited; break-glass changes are imported or reverted through code.
- Database/key/contract changes use expand-and-contract, compatibility evidence, and forward repair. Rollback never assumes that committed security state or migrations can be erased safely.
- Incident exercises and restore/key-rotation/outbox-replay drills occur before production and at a documented cadence thereafter.

### Capacity and cost gates

- Load tests cover peak authorization callbacks, token refresh bursts, passkey verification, global logout/security-version fanout, outbox backlog recovery, and abusive traffic while measuring cryptographic and database bottlenecks.
- Scale stateless application/relay instances horizontally; protect PostgreSQL with bounded pools and backpressure. Do not introduce a new stateful platform solely to improve an unmeasured bottleneck.
- Budgets and anomaly alerts cover compute, database/storage/backup, key operations, messaging, logs/traces, SMS/email delivery, WAF/egress, and export storage. Security telemetry is sampled only where doing so cannot omit required audit/security evidence.
- Triggers for architectural change are measurable: sustained SLO breach, connection/CPU/storage thresholds, outbox recovery time, key-operation limits, failure-domain blast radius, restore objectives, compliance, or cost—not anticipated portfolio size alone.

### Cloud-design reconciliation gate

Before this Wayfinder can be treated as infrastructure-ready, import the separate cloud solution's decisions for:

1. provider, account/project/subscription and region strategy;
2. public edge, DNS/TLS/WAF and private network topology;
3. compute/runtime and independent failure domains;
4. managed PostgreSQL topology and IAM physical-isolation decision;
5. topic/queue, ordering, DLQ, and replay services;
6. cache/replay-counter service and degraded behavior;
7. KMS/HSM, secrets, key policy, rotation, and audit products;
8. encrypted backup, object/export storage, retention, and deletion;
9. telemetry, alert routing, incident access, and cost budgets; and
10. measured SLO/RPO/RTO feasibility and recurring cost.

No provider-specific choice in older Dutch documents silently becomes the portfolio IAM decision. Those documents are evidence/input to the cloud-solutions reconciliation, not authority for this ticket.
