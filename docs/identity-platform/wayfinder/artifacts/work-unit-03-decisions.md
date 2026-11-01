# Work Unit 03 Decision Record: Transaction, Outbox, and Audit Persistence

**Status:** accepted for implementation  
**Scope:** foundational PostgreSQL 18 persistence primitives only  
**Depends on:** Work Units 1 and 2 contracts

## Boundary

Work Unit 3 introduces Flyway V2 persistence for immutable event facts, mutable delivery attempts, and minimal allowlisted audit facts. It also introduces transaction/repository ports and PostgreSQL adapters needed to prove atomicity, optimistic concurrency, permissions, and recovery. It does **not** add Human Identity, identifier, challenge, app registration, App Subject, activation, authorization, or other Slice A/B/C tables.

There is no generic production “aggregate” table. Atomic aggregate-plus-outbox behavior is exercised with a test-only integration fixture created and removed by the test harness. Later work units add their own domain tables and use the same transaction boundary.

## V2 relational model

All timestamps are `timestamptz`, generated IDs are bounded `text` with contract-equivalent checks, counters/versions are `bigint` with `>= 1` checks, and serialized contract data is `jsonb`. Application SQL is parameterized; identifiers and SQL fragments are never accepted from runtime input.

### `outbox_event` — immutable published fact

Columns:

- `event_id text primary key`, matching `^evt_[A-Za-z0-9_-]{16,128}$`;
- `event_type text`, exactly `iam.app-subject.onboarding-ready.v1` for this milestone;
- `schema_version bigint`, exactly `1` for the registered event;
- `occurred_at timestamptz`;
- `producer text`, exactly `iam`;
- `environment text`, constrained to `development|test|staging|production`;
- `aggregate_type text`, exactly `APP_ONBOARDING`;
- `aggregate_id text`, matching `^[A-Za-z][A-Za-z0-9_-]{2,128}$`;
- `aggregate_version bigint >= 1`;
- `correlation_id text`, generated and matching `^cor_[A-Za-z0-9_-]{16,128}$`;
- nullable `causation_id text`, generated and matching `^cau_[A-Za-z0-9_-]{16,128}$` when present;
- `destination_app_registration_id text`, matching `^[a-z][a-z0-9-]{2,63}$`;
- `payload jsonb`, required to be a nonempty JSON object with at most 32 top-level keys;
- `payload_fingerprint char(64)`, lower-case hexadecimal SHA-256;
- `recorded_at timestamptz`, the database insertion time.

The relay reconstructs the exact contract envelope from these columns. `destination` is intentionally represented by the single explicit `destination_app_registration_id` column—not a routing map—because the v1 envelope permits exactly one `appRegistrationId`. The payload remains event-schema-specific JSON and is validated against the registered schema before insertion; WU3 does not invent an open-ended event payload.

The logical-event unique key is:

`(producer, event_type, schema_version, aggregate_type, aggregate_id, aggregate_version, destination_app_registration_id)`.

It permits exactly one event fact for one aggregate version and destination app. The current registry is deliberately closed to onboarding-ready v1; a future event type requires a migration, closed payload value, and database validator. Application and database validation enforce aggregate ID = payload `activationId`, aggregate version = payload `onboardingVersion`, and destination app = payload `appRegistrationId`.

An idempotent retry must reproduce the complete immutable event fact: event ID, event/schema type, occurrence instant, producer/environment, aggregate coordinates, correlation and nullable causation IDs, destination, and canonical payload fingerprint. The logical key prevents a second fact, but a different event ID or any different immutable field is a conflict rather than a successful retry. Audit and initial delivery retries follow the same rule: the complete persisted immutable/initial content must match.

### `outbox_delivery` — mutable transport state

Columns:

- `event_id text` referencing `outbox_event(event_id)`;
- `destination_name text`, a bounded configured transport endpoint name, not an app identifier or URL;
- `state text`, constrained to `PENDING|LEASED|ACKNOWLEDGED|QUARANTINED`;
- `attempt_count integer >= 0`;
- immutable `initial_available_at timestamptz`, preserving the original intent across every mutable state;
- `available_at timestamptz`;
- nullable `lease_owner text` and `lease_expires_at timestamptz`;
- nullable `acknowledged_at timestamptz`;
- nullable `last_failure_code text`, containing only a bounded allowlisted machine code—never exception text or payload data;
- `version bigint >= 1` for expected-version updates;
- `created_at` and `updated_at timestamptz`.

Primary key: `(event_id, destination_name)`. State checks require lease owner/expiry only while `LEASED`, acknowledgement time only while `ACKNOWLEDGED`, and prevent acknowledged/quarantined rows from retaining a lease. Delivery claiming uses a bounded ordered query with `FOR UPDATE SKIP LOCKED`, followed by an expected-version update. Publishing happens after the claim transaction commits; acknowledgement is a later expected-version update. An expired lease becomes claimable again, so publish-before-ack duplication is expected and safe.

`destination_name` identifies transport delivery configuration; `destination_app_registration_id` remains the privacy/security boundary carried by the event. They are not interchangeable. Callers never supply `destination_name`. A migration-owned route registry derives it from the stored `(event_type, destination_app_registration_id)`. This milestone registers only `(iam.app-subject.onboarding-ready.v1, dutch-development) -> dutch-ums-onboarding`; adding another app/route is a versioned registration change.

Application code creates delivery intent only through the closed `InitialDelivery(eventId, availableAt)` command and the `append_initial_delivery` database function. That function can represent only pristine `PENDING`, attempt `0`, version `1`, with no lease, acknowledgement, or failure. An exact retry compares event ID, derived route, and immutable `initial_available_at`, so it remains idempotent after claim, acknowledgement, or quarantine. Runtime and relay have no direct table `INSERT`.

### `audit_fact` — immutable allowlisted security/operation fact

Columns:

- `audit_id text primary key`, matching `^aud_[A-Za-z0-9_-]{16,128}$`;
- `fact_type text`, constrained initially to `OUTBOX_EVENT_RECORDED|OUTBOX_DELIVERY_QUARANTINED`;
- `subject_kind text`, constrained to `SYSTEM|APP_REGISTRATION|EVENT`;
- nullable `subject_id text`, constrained by kind: absent for `SYSTEM`, the app-registration contract pattern for `APP_REGISTRATION`, and the event-ID contract pattern for `EVENT`;
- `outcome text`, constrained to `SUCCEEDED|REJECTED|FAILED`;
- `correlation_id text` and nullable `causation_id text`, using the event-envelope bounds;
- nullable `event_id text` referencing `outbox_event` without delete cascade;
- nullable `reason_code text`, constrained initially to `RETRY_EXHAUSTED|NON_RETRYABLE_FAILURE` and permitted only for the quarantine fact;
- `occurred_at timestamptz` and `recorded_at timestamptz`.

There is no free-form details/metadata JSON, actor PII, identifier, token, credential, stack trace, or exception message. New fact types, subject kinds, or reason codes require a migration and tests.

## Canonical JSON and fingerprinting

`payload_fingerprint` is SHA-256 over the UTF-8 bytes of the payload serialized with RFC 8785 JSON Canonicalization Scheme semantics. Fingerprints are computed through one application capability before repository insertion and verified in tests against fixed language-neutral vectors. PostgreSQL `jsonb::text`, ordinary Jackson serialization, map insertion order, whitespace, and database locale are not canonicalization algorithms and must not be used as the digest input.

The fingerprint is an integrity/idempotency signal, not a secret and not authentication. Tests compare digests without logging the payload. The repository rejects a caller-supplied fingerprint that does not equal the capability result.

PostgreSQL does not recompute RFC 8785. The event-specific Java adapter accepts only the closed onboarding payload and computes/verifies the fingerprint through the canonicalization capability. The database function is granted only to runtime, parses payload text inside its sanitized exception boundary, validates the registered payload, and compares both stored `jsonb` equality and fingerprint on retry. A matching fingerprint with different payload is a conflict.

## Immutability and deletion

`outbox_event` and `audit_fact` are append-only:

- application/relay roles receive `SELECT` plus execute only on narrowly scoped append/transition functions, with no direct `INSERT`, `UPDATE`, `DELETE`, or `TRUNCATE` on messaging tables;
- database triggers reject `UPDATE` and `DELETE`, including attempts by a table-owning migration session during normal operation;
- foreign keys use `RESTRICT`/`NO ACTION`, never cascade from delivery or audit data into an event;
- adapters expose append/find operations only—no update/delete API.

Schema evolution and an eventual approved retention job may use a separately controlled migration/maintenance path that explicitly disables or replaces enforcement. Retention duration, partitioning, archival, and erasure mechanics are deferred until legal/operational requirements exist; WU3 performs no pruning.

## Transactions and repository behavior

A Spring transaction coordinator accepts repository ports and writes domain state, its audit fact, the outbox event, and initial delivery row in one short local database transaction. Any exception before commit rolls all writes back. Repository inserts and state transitions report duplicate/optimistic-conflict outcomes explicitly; they do not silently swallow them.

Expected-version mutation has the form `... WHERE id = ? AND version = ?`, increments the version once, and succeeds only when exactly one row changes. WU3 proves this on delivery state and through a test-only aggregate fixture; later domain repositories adopt the same contract. Process-local locks are not part of correctness.

Delivery completion is also fenced by the current lease owner. Relay identities have no table-level `UPDATE`; claim, acknowledgement, and quarantine use fixed-SQL, fixed-`search_path`, security-definer database functions with explicit execute grants. These functions constrain mutable columns and require state, version, and owner predicates so a stale or different worker cannot complete a lease.

## Database roles and provisioning boundary

Production infrastructure provisions databases, login credentials, and membership in pre-existing NOLOGIN privilege roles. No password, connection secret, cloud identity, or login role is embedded in Flyway migrations or application configuration defaults.

The expected privilege roles are:

- `iam_migrator`: owns the IAM schema/objects and runs Flyway; it is not the runtime identity;
- `iam_runtime`: schema usage, required read access, and execute on narrowly scoped exact-retry append functions for registered events, audit facts, and pristine initial delivery intents; no direct messaging-table insert or mutation;
- `iam_relay`: schema usage, read access to event/delivery rows, and execute on fenced claim/acknowledge/quarantine functions; no direct messaging-table insert or mutation and no audit access.

Flyway owns grants on each versioned object and alters default privileges for future objects only where intentional. Its connection executes `SET ROLE iam_migrator` before schema history or versioned SQL, so ownership/default privileges attach to the NOLOGIN role rather than its ephemeral login member. It fails clearly if externally provisioned privilege roles are absent. Testcontainers bootstrap creates non-secret ephemeral login/group roles before Flyway and connects separately as migrator, runtime, relay, and an unrelated-service role. This mirrors the production boundary without treating test credentials as deployable credentials. Neither runtime role receives `CREATE` on the database/schema or access to unrelated schemas.

## Operational policy is configuration

Batch size, maximum attempts, backoff, jitter, polling, quarantine threshold, and destination mapping are typed validated configuration supplied per environment. Production code contains no credential, endpoint, or security-sensitive operational default. Lease duration is a whole number of seconds from 1 through 900 (15 minutes), enforced by both adapter and database function. Other bounds fail startup when absent or unsafe in production-like profiles; tests provide explicit deterministic values and clocks.

## Required PostgreSQL 18 integration matrix

All cases run against PostgreSQL 18—never H2—and fail rather than skip when the container runtime is unavailable:

1. Flyway migrates a clean empty schema and validates successfully.
2. Flyway migrates a retained V1 test snapshot to V2, preserving prior data, then validates; re-running is a no-op.
3. Every contract-format, enum, JSON-object/cardinality, state-consistency, foreign-key, primary-key, and logical-event uniqueness constraint has a positive and negative case.
4. A valid onboarding fixture round-trips with exact field types; nullable `causationId` remains null, timestamps retain instants, and large valid versions do not narrow to 32-bit application types.
5. Fixed RFC 8785 vectors prove semantically identical reordered JSON has one SHA-256 fingerprint, while any value/type change differs.
6. Injected failures before domain-fixture write, after domain-fixture write, after event append, after audit append, and after delivery creation leave either the complete committed set or no visible set.
7. Concurrent insertion of the same logical event has one winner/fact; an exact retry observes the existing fact. Different logical onboarding versions/destinations remain independently insertable. Different event types/schema versions are deliberately negative until a migration registers them.
8. `outbox_event` and `audit_fact` updates/deletes fail both through repository absence and direct SQL, including with the migration owner while triggers are enabled.
9. Two relay workers using `SKIP LOCKED` never claim the same live lease; expected-version races have one winner; expired leases are reclaimable after restart.
10. Publish-before-ack leaves a reclaimable delivery and supports duplicate publication; acknowledgement and quarantine state constraints reject invalid combinations.
11. Runtime, relay, migrator, and unrelated-service role matrices prove every allowed operation and deny cross-role/cross-schema reads and writes. In particular, runtime/relay cannot mutate immutable facts and the unrelated role cannot read IAM tables.
12. Restart recovery proves committed pending/leased rows remain durable and can resume without process memory.
13. Canary values resembling email, phone, credentials, authorization codes, and tokens are rejected from allowlisted audit fields and are absent from captured SQL errors and application logs.

## Deferred decisions

Transport technology, broker topic naming, deployment topology, table partitioning, retention periods, archival, and production lease/backoff values are deliberately deferred. They do not affect the stable transaction and persistence contracts above. There is no unresolved blocker to implementing WU3.
