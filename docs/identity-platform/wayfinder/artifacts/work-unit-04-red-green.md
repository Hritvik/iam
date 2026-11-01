# Work Unit 04 RED/GREEN Evidence

## Scope delivered

Protected Human Identity, verified email/phone identifiers, purpose-separated cryptographic protection,
verification challenges, PII-free lifecycle audit facts, and PostgreSQL persistence were added without
HTTP, activation, App Subjects, fixture loading, or integration-event publication.

## RED

The first targeted run was:

```text
./gradlew test --tests 'dev.distracted.iam.identity.*'
```

It failed in `compileTestJava` with 40 missing-symbol errors for the intentionally absent normalization,
AAD, structured sealed-value, blind-index, challenge-digest, and encryption capabilities. No production
implementation existed at that point.

During W-1 correction, the per-index rollback regression was run independently:

```text
./gradlew integrationTest --tests '*failureAfterFirstRequiredRotationIndexRollsBackEveryPromotionEffect' --rerun-tasks
```

It failed at `IdentityPersistenceIntegrationTest.java:357`: verification completed instead of throwing at the first
required rotation-index seam. The implementation exposed only a batch-level seam. Moving the observer to each
successful index insert made the same test pass and proved the surrounding transaction removes the consumed state,
identifier, every index, security-version update, and verification audit fact.

The first clean quality run later proved all tests and contract validation green but failed the quality
gate on Checkstyle (33 one-statement-per-line findings), secret scanning (a test credential variable name),
and 74% branch coverage. The formatting and safe generated-test-credential naming were corrected and
additional boundary/state tests raised branch coverage without lowering the configured threshold.

## GREEN

Final clean command:

```text
./gradlew clean test integrationTest check contractBundle --warning-mode all
```

Result: `BUILD SUCCESSFUL`, 19 actionable tasks, with unit, PostgreSQL 18 integration, language-neutral
contract, Checkstyle, dependency policy, SBOM, secret scan, and aggregate coverage verification green.

- Unit tests: 71, zero failures/errors/skips
- PostgreSQL integration tests: 37, zero failures/errors/skips
- Contract tests: 8, zero failures/errors/skips
- Aggregate line coverage: 92.53% (669 covered, 54 missed)
- Aggregate branch coverage: 80.28% (350 covered, 86 missed)
- Contract bundle SHA-256: `fadba94390448f36cb0def04be812683841b8887e64e3d5e049b9d359146ff6f`

## Security and persistence evidence

- ICU4J 78.1 supplies pinned UTS #46 non-transitional processing with STD3, Bidi, and ContextJ checks.
- E.164 input is exact and region-free.
- Full 32-byte HMAC-SHA-256 values use distinct identifier and challenge grammars/capabilities.
- Blind-index policy exposes readable and required-write versions. Resend compares with the challenge's persisted
  key version; promotion retains that index and derives every required write index from authenticated plaintext.
  Integration tests retire the old read key and still resolve the promoted identity through the new index.
- AES-256-GCM uses fresh 96-bit nonces, 128-bit tags, structured values, and length-delimited AAD.
- Provider failures are mapped to stable messages without retaining provider exception causes.
- Protected byte values defensively copy on construction/access and have non-revealing `toString()` output.
- V3 adds constrained identity, verified-identifier, rotation-safe blind-index, and challenge tables with
  restrictive foreign keys and runtime/migrator grants. Runtime has no table UPDATE privilege; narrowly scoped
  `SECURITY DEFINER` functions enforce state, expected-version, and time predicates, with PUBLIC execution revoked.
- Challenge acceptance uses PostgreSQL `transaction_timestamp()`; expiry accepts no code at the boundary.
- Transition functions accept no caller timestamp. A runtime attempt to invoke the removed forged-time signature fails,
  while concurrent expiry/verification ends in one legal terminal state.
- Duplicate canonical promotion rolls back consumption and every effect. Concurrent correct/correct
  verification creates one identifier; a racing or later replay receives the same generic rejection because WU4
  intentionally exposes no trusted idempotency context.
- Database snapshots assert ciphertext/HMAC storage, immutable allowlisted audit facts, and zero WU4
  outbox events.
- Per-test truncation isolates WU4 rows. PostgreSQL races cover issue, resend, correct/correct, correct/wrong,
  max-attempt, expiry/verify, and duplicate promotion. Restart tests recreate application adapters and preserve attempt
  budgets and terminal states. Duplicate tests cover phone, equivalent UTS #46/domain forms, and case-sensitive locals.
- Privacy canaries are checked against protected database snapshots, audit/outbox/delivery rows, application logs,
  PostgreSQL logs, exception-safe results, and serialized domain values. A post-run report scan found no canary match.
- Production-like startup now requires externally supplied, self-checked, version-addressable encryption,
  blind-index, and challenge-digest keyrings. Rotation tests prove old challenges and identifiers remain readable
  while new rows use active write versions. Startup rejects key-reference reuse across cryptographic purposes.

## Maintenance and deferred integration

The retained-V1 migration test's expected migration count changed from one to two because latest now applies
both V2 and V3; its preserved-data and no-op rerun assertions remain intact. Delivery channel/UX, rate limits,
multiple identifiers of one type, identifier change/removal, key-provider custody, retention/erasure, HTTP,
activation, App Subjects, and production event publication remain assigned to later work units.
The repository has dependency locking, verification metadata, and an SBOM, but no configured dependency
vulnerability scanner. Adding an approved scanner remains an integration gap and is not claimed as completed.
