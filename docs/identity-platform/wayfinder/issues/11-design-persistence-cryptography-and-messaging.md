Type: grilling
Status: resolved
Assignee: Codex
Parent: [Specify the shared first-party Identity Platform](../map.md)
Blocked by: 06, 08, 10

# Design persistence, cryptography, and transactional messaging

## Question

What schemas, transaction boundaries, identifier protection, credential/token storage, concurrency controls, key-versioning rules, outbox/inbox semantics, event ordering, reconciliation, and database isolation durably implement the settled model without copying PII into consumers?

## Decision

### Database ownership and schema boundaries

- IAM exclusively owns one PostgreSQL database per environment. Applications, UMS, analytics, support tools, and event consumers have no table, schema, replica, or backup access. Cross-service integration uses versioned APIs and events only.
- Physical infrastructure may initially be shared for cost, but database names, roles, credentials, migrations, backups, network policy, and ownership remain service-specific. A shared PostgreSQL instance never permits cross-service joins.
- Flyway migrations are forward-only, checksum-protected, exercised against empty and previously released schemas, and compatible with rolling application deployment. Destructive retirement uses expand/migrate/verify/contract phases and restore-tested backups.
- Separate relational aggregates/tables model Human Identity, Verified Identifier, Authentication Factor, Platform SSO Session, App Subject/Activation, OAuth authorization/grant/code, refresh family/member, App/Client/Resource Registration, Workload Identity/credential, Delegation Workflow, security version, recovery/deletion workflow, audit record, outbox event, and reconciliation checkpoint. Avoid a generic JSON identity record as the source of truth.
- Flexible policy/configuration may use validated versioned JSONB alongside indexed relational ownership/state columns; security invariants remain database constraints and application rules, not unvalidated document conventions.

### Identifiers and PII protection

- Normalize identifiers inside the trusted IAM boundary using a versioned type-specific algorithm before comparison. Email and E.164 phone normalization are distinct; unsupported types fail closed.
- Store the display/canonical identifier value using authenticated application-layer envelope encryption. Each row records ciphertext, nonce/IV as required, algorithm suite, encrypted data-key reference/material, key version, normalization version, type, lifecycle state, and timestamps. Database/storage encryption remains mandatory defense in depth but is not the only protection.
- Enforce lookup and active-identity uniqueness through a separate keyed blind index computed with an environment- and identifier-type-separated HMAC key over the normalized value and normalization version. Never use an unkeyed hash. Blind indexes are still sensitive security data and are excluded from events/logs.
- Support blind-index and encryption-key rotation with overlapping versions, deterministic backfill/re-encryption, uniqueness checks across active versions, resumable progress, and measured completion before retiring an old key.
- Decryption is available only to narrow IAM application capabilities. Ordinary authentication comparisons use blind indexes; logs, traces, metrics, SQL diagnostics, events, and errors use opaque references or reason codes.

### Secrets, factors, and tokens

- Password storage is absent from the initial design. If passwords are introduced later, they require a separate decision and memory-hard password hashing policy.
- WebAuthn stores credential ID, public key, RP/user binding, counters and backup/attestation policy data needed for verification; never a private key. Credential IDs and device metadata are security-sensitive and not published.
- Authorization codes, refresh tokens, OTPs, recovery codes, session handles, administrative grants, DPoP replay IDs, and similar bearer/one-time artifacts are generated from a CSPRNG and stored only as versioned protected digests. Recovery codes use an appropriately slow password-style digest in addition to attempt limits; high-entropy machine tokens use keyed digests suitable for indexed lookup.
- Raw token/artifact values exist only transiently for issuance/verification, are never recoverable from persistence, and are cleared from structured diagnostic context. A production secret or signing key is never supplied by a migration or default configuration.
- Signing and client-verification keys use explicit purpose, algorithm, version, activation, retirement, compromise, and provenance metadata. Private signing operations occur through the approved key-management interface; persistence stores public keys and external key references, not exportable production private keys.

### Transactions and concurrency

- Each accepted command uses one short local database transaction for authoritative aggregate changes, optimistic version advancement, idempotency outcome where applicable, audit fact, and outbox rows. No network call, notification delivery, broker publish, key-management round trip that can be prepared beforehand, or user interaction occurs inside the transaction.
- Aggregate roots carry monotonic versions. Updates use expected-version predicates and database uniqueness/check/foreign-key constraints. A stale command receives an explicit conflict or safe idempotent outcome; last-write-wins is prohibited for security state.
- Operations requiring a single winner—identifier attachment, authorization-code consumption, refresh rotation, recovery-code use, challenge use, App Subject creation, and finalization—use unique constraints plus row locking/conditional update as appropriate.
- Idempotency keys are namespaced by authenticated actor/client, operation, and target; request fingerprints prevent key reuse with a different command. Stored responses contain no reusable token or secret.
- Use the weakest transaction isolation that proves each invariant, with explicit locking/constraints. Multi-aggregate global security operations may use repeatable/serializable transactions or deterministic locked batches with a durable workflow when one bounded transaction is unsafe.

### Transactional outbox

- Every externally relevant lifecycle change writes immutable outbox rows in the same transaction as its source state. This guarantees source commit plus durable publish intent, not end-to-end exactly-once delivery.
- Each row includes event ID, event type/schema version, producer, environment, occurred time, aggregate type and opaque ID, monotonic aggregate version, correlation ID, causation ID, canonical PII-free payload, publish state, attempt metadata, and trace context that contains no baggage/PII.
- Event payload construction uses explicit allowlisted contract types. Serializing domain entities, persistence rows, exception objects, headers, or arbitrary maps into events is prohibited.
- A polling relay initially claims bounded batches with transaction-safe row claiming, publishes outside the source transaction, and marks acknowledgement afterward. A crash after publish and before acknowledgement produces a duplicate by design.
- Partition/message-group keys preserve order only within the documented aggregate stream. Consumers never infer global ordering across identities, apps, or event types.
- Outbox lag, oldest unpublished age, attempts, poison events, broker acknowledgement, and reconciliation variance are observable. Events are never silently discarded; controlled quarantine/DLQ handling preserves immutable event identity and payload.

### Consumer inbox and projections

- Every state-changing consumer records event ID and producer identity transactionally with its local effect and its own outbox facts. Duplicate delivery returns success without repeating the effect.
- Consumers track the latest aggregate version where ordering matters. Gaps pause that aggregate, trigger retry/reconciliation, and do not cause speculative state. Older events are safely ignored only under an explicit version rule.
- A unique domain constraint, not inbox deduplication alone, guarantees one app-owned profile/mapping per App Subject or Identity mapping contract.
- Consumers validate the envelope and exact schema version, producer, environment, destination/routing, aggregate semantics, size limits, and PII-negative contract before processing. Unknown incompatible versions quarantine rather than deserialize permissively.
- Reconciliation compares producer-authoritative PII-free lifecycle state/version with consumer checkpoints through a bounded privileged API or replay process. It does not grant consumers database access or expose raw identifiers.

### Audit and retention

- Audit records are append-only at the application layer, schema allowlisted, integrity protected through a chained/batched cryptographic evidence mechanism or equivalent managed immutable archive, and exported under retention policy before operational deletion where required.
- Operational tables use explicit retention/finalization jobs for expired codes, tokens, replay state, sessions, event delivery metadata, exports, and deletion workflows. Removing operational records does not erase required minimal audit evidence or resurrect retired identifiers.
- Backups are encrypted, access controlled, retention bounded, restoration rehearsed, and treated as containing PII. Deletion documentation honestly states backup expiry behavior; deleted data is not restored into active service without replaying deletion tombstones/finalizers.

### Messaging portability

- Event contracts, outbox/inbox correctness, aggregate ordering, and idempotency do not depend on a specific broker's exactly-once or FIFO claims.
- Initial transport may use the selected cloud's managed topic/queue service, but adapters must preserve event ID, aggregate ordering key, correlation/causation, delivery attempts, DLQ routing, encryption, and least-privilege producer/consumer identity.
- Replacing the transport cannot change event meaning or permit payload enrichment with PII.
