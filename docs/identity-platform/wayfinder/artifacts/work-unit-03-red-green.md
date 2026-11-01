# Work Unit 03 RED/GREEN Evidence

## Scope

Work Unit 03 adds only the accepted transaction, immutable outbox/audit, and mutable delivery-state persistence primitives. It does not add identity, registration, activation, authorization, or transport technology.

## RED

The first production-facing behavior was specified in `Rfc8785PayloadFingerprintTest` and the first PostgreSQL 18 migration expectation in `WorkUnit03MigrationIntegrationTest` before implementation.

Command:

```text
./gradlew test --tests '*Rfc8785PayloadFingerprintTest' integrationTest --tests '*WorkUnit03MigrationIntegrationTest'
```

Observed failure:

```text
compileTestJava FAILED
cannot find symbol: class Rfc8785PayloadFingerprint
```

This was a behavioral RED caused by the absent capability and V2 persistence surface, not test infrastructure or container setup.

## GREEN and refactor

The minimal implementation introduced:

- PostgreSQL V2 immutable `outbox_event` and `audit_fact` facts, mutable versioned `outbox_delivery`, explicit checks, append-only triggers, and least-privilege externally provisioned roles;
- immutable Java records and small persistence ports;
- parameterized Spring JDBC adapters, local Spring transaction runner, expected-version acknowledgement/quarantine, and bounded `FOR UPDATE SKIP LOCKED` claiming;
- RFC 8785 canonical JSON SHA-256 through the pinned `java-json-canonicalization` library;
- privacy-safe adapter error translation that does not propagate rejected parameter values;
- a closed, schema-equivalent onboarding payload value that rejects raw/generic JSON, PII-shaped values,
  global identity IDs, token/credential canaries, cross-app semantic mismatches, and unregistered enum values;
- owner-and-version fenced security-definer transition functions; relay has no arbitrary table `UPDATE`;
- exact full-content retry comparison for events, audit facts, and initial delivery intents;
- PostgreSQL 18 tests for clean and retained-V1 migrations, validation/no-op rerun, logical retry/collision behavior, rollback, direct immutable-row mutation denial, role boundaries, concurrent claiming, expected-version races, lease recovery, and unsafe policy rejection.

Targeted GREEN commands:

```text
./gradlew test --tests '*Rfc8785PayloadFingerprintTest' integrationTest --tests '*WorkUnit03MigrationIntegrationTest' --write-locks
./gradlew integrationTest --tests '*MessagingPersistenceIntegrationTest'
./gradlew integrationTest --tests '*WorkUnit03MigrationIntegrationTest'
```

Review then supplied additional behavioral REDs for ownerless completion, arbitrary relay mutation, raw JSON,
non-exact retries, and superuser-masked role checks. The corrective GREEN uses separate ephemeral migrator,
runtime, relay, and unrelated-service logins; a separately owned unrelated schema; fenced transition functions;
and collision/privacy tests. All targeted suites passed after implementation/refactoring.

A second re-review added REDs for arbitrary initial-delivery construction, unregistered event types/constants,
free-form correlation/causation IDs, unbounded or expired leases, and Flyway login ownership. The final GREEN
uses a closed `InitialDelivery` command, function-only pristine delivery append, a database-closed onboarding
event registry, generated prefixed persistence IDs, a 1–900 second whole-second lease bound, live-lease
completion predicates, and Flyway connection initialization with `SET ROLE iam_migrator`.

A fourth review exposed mutable-state coupling in delivery retry and caller-selected routing. The final model
preserves `initial_available_at`, derives the route from a migration-owned registry, and compares only immutable
creation identity for delivery retries. Event retries compare stored payload JSON as well as the application-
computed RFC 8785 fingerprint. All function parsing and integrity failures—including NOT NULL and malformed
JSON—are translated inside the security-definer boundary without submitted values.

The privacy evidence is non-vacuous: with a root application-log appender attached, the integration test invokes
the actual `JdbcOutboxEventRepository` fingerprint-rejection path and the direct sanitized database rejection
paths. It scans every exception-cause message, every captured application event, and the PostgreSQL 18 container
logs for runtime-created canaries. Failures use generic assertions that never include the canary value.

## Constraint coverage map

| Declared invariant | Positive coverage | Negative/collision coverage |
|---|---|---|
| Registered event ID/type/schema/producer/environment/aggregate constants | `appendsRoundTripsAndDeduplicatesLogicalEvents`, `preservesNullabilityInstantsAndVersionsBeyond32Bit` | `rejectsNullVersionsReasonsAndEnvelopeSemanticMismatches`, `databaseAppendFunctionsRejectUnregisteredConstantsAndCanariesWithoutEcho` |
| Correlation/causation/event/audit identifier grammars | normal event/audit round trips | `PersistenceIdentifierTest`, database canary test |
| Closed payload keys, constants, types, app/aggregate/version bindings | all event append tests | payload/privacy tests and raw database append negatives |
| Fingerprint format, application recomputation, payload equality | RFC 8785 vector and exact retry tests | mismatch plus forged-fingerprint/different-payload test |
| Event primary/logical uniqueness and exact retry identity | sequential and concurrent exact retries | event-ID/logical collisions; independent logical version/destination tests |
| Event/audit immutability and restrictive foreign keys | committed fact tests | owner direct update/delete and malformed audit/FK tests |
| Initial delivery pristine state, derived route, PK, immutable availability | initial append and registered-route test | changed intent, unregistered route, and direct INSERT denial |
| Delivery state/attempt/version/lease/ack/failure consistency | claim, reclaim, acknowledge, quarantine | malformed direct states, wrong owner/version, expired lease, invalid reason |
| Lease/batch bounds and concurrency | two-worker `SKIP LOCKED` claims | zero/negative/fractional/overlong lease and invalid batch tests |
| Audit fact-type/subject/outcome/event/reason semantics | recorded and quarantined fact constructors/rows | semantic, identifier, canary, and SQL constraint negatives |
| Role/default/PUBLIC/cross-schema privileges | allowed runtime/relay/migrator/unrelated operations | full direct mutation/insert/read/execute denial matrix |
| Sanitized application logs and client errors | captured empty/safe logging path | full causal-chain malformed JSON, NULL, audit, delivery, and privacy-canary assertions |

## Supply-chain changes

The RFC 8785 implementation is pinned at `io.github.erdtman:java-json-canonicalization:1.1`. Gradle dependency locks and SHA-256 verification metadata were regenerated for every configuration. No credential, endpoint, login role, password, or production retry policy was added.

## Remaining integration boundary

This unit validates the accepted onboarding-ready v1 payload through a closed application value and a database check before durable insertion. Later event types require their own registered closed value and database validator; there is no generic JSON escape hatch. This unit deliberately does not publish to a broker. Broker choice, destination mapping, production lease/backoff values, retention, and archival remain deferred by the accepted decision record.

## Final verification

```text
./gradlew clean test integrationTest check contractBundle jacocoTestReport --warning-mode all
BUILD SUCCESSFUL
```

- unit: 36 passed;
- PostgreSQL 18 integration: 19 passed;
- contract: 8 passed;
- JaCoCo: 92.7% line, 84.2% branch;
- Checkstyle, dependency policy, SBOM, secret scan, Flyway validation, contract validation, ZIP checksum,
  and archive integrity: passed.
