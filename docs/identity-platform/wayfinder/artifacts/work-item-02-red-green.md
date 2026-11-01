# Work Item 02 — RED/GREEN Evidence

Date: 2026-10-24

Scope: deterministic development/test identity fixture plus profile-neutral EMAIL_OTP factor and VERIFIED_EMAIL recovery evidence. Canonical contracts, authorization, activation, messaging semantics, Dutch, and UMS were not changed.

## Behavioral RED → GREEN sequence

1. **Persistence contract RED.** `IdentityEvidenceContractTest.v4DefinesClosedFactorRecoveryEvidenceAndLeastPrivilegeFunctions` failed because the V4 migration resource did not exist. **GREEN:** V4 adds closed factor/recovery evidence, append-only triggers, database-clock timestamps, closed audit facts, fixed-SQL `SECURITY DEFINER` ensure functions, and runtime SELECT/function-execute access without direct mutation grants.
2. **Application boundary RED.** `IdentityEvidenceApiPresenceTest.exposesOnlyBoundedEnsureOperationsAndTypedResults` failed with `ClassNotFoundException` because no evidence application API existed. **GREEN:** the API exposes only the two normal ensure operations and typed `CREATED`, `EXISTING`, `REJECTED`, and `CONFLICT` outcomes, with CSPRNG opaque IDs and non-revealing errors/results.
3. **Fixture receipt RED.** `FixtureReceiptPresenceTest.fixtureReceiptIsInternalAndNotAProductionIdentityPort` failed because the internal one-shot receipt boundary did not exist. **GREEN:** the gated delivery adapter uses a bounded in-memory store, atomically removes a code on take, clears on close/failure, and has no endpoint, serializer, or revealing string representation.
4. **Verification RED.** The first complete gate exposed a retained-migration expectation still pinned to V3, a secret-scan false positive from a test variable name, and branch coverage of 76%. **GREEN:** the retained migration expectation includes additive V4, test credentials use a non-secret-bearing symbol name, and focused safety/outcome tests bring aggregate coverage above both 80% thresholds.
5. **Exact gate RED.** Opt-in with `development,qa` and `test,local` reached fixture configuration instead of failing the safety guard. **GREEN:** when opt-in is true, the complete active-profile set must be non-empty and a subset of `{development,test}`; unknown, production-ish, and mixed profiles return only `fixture_profile_forbidden`.
6. **Purpose separation RED.** The fixture capability gate accepted all six pairwise key-reference reuse combinations. **GREEN:** encryption, blind-index, challenge-digest, and signer metadata must expose four distinct references after every capability passes its typed health/purpose/algorithm check.
7. **Production-like assembly RED.** The normal Identity Service rejected a healthy `production-like` graph as an unknown crypto environment. **GREEN:** normal service assembly maps `production-like` onto the stable `production` cryptographic domain, while the independent fixture guard continues to reject fixture opt-in.
8. **Complete graph RED.** The first real Spring fixture graph lacked an `IdentityService` because conditional bean discovery ran before the fixture delivery definition. **GREEN:** profile-neutral identity configuration owns assembly and the fully gated fixture graph injects the ordinary delivery port. Two complete Spring contexts over the same PostgreSQL database converge on one identity and one evidence set.
9. **Restart-key RED.** Recreating a context with newly generated test keys could not resolve the protected fixture identifier and created a second identity. **GREEN:** the restart test now injects one purpose-separated, randomly generated non-production key set into both contexts, matching real restart key continuity without embedding key material.
10. **Audit pairing RED.** V4 initially allowed a valid-shaped recovery subject for `AUTHENTICATION_FACTOR_REGISTERED` and the inverse pair. **GREEN:** database semantics now require the exact fact-type/subject-kind pair for each evidence milestone.
11. **Architecture RED.** Complete fixture service assembly temporarily introduced JDBC and transaction dependencies into the fixture package. **GREEN:** assembly returned to the profile-neutral identity configuration; fixture code again depends only on identity and typed capability ports.
12. **Rotated-key separation RED.** The fixture gate checked only active metadata references and accepted overlap in historical/readable version maps. **GREEN:** it now unions every encryption, blind-index, and challenge-digest `keyReferences().values()` entry with the signer reference, rejects null/empty/blank maps or references, and rejects duplication both within one purpose and across purposes.

Only observed behavioral failures are listed. Compile and setup corrections were not treated as RED evidence.

## Implemented behavior

- `authentication_factor` and `recovery_method` persist only opaque references, closed evidence types/states, versions, and PostgreSQL transaction timestamps.
- Evidence creation derives the verified EMAIL inside the database function. The caller cannot submit an identifier, type, state, timestamp, SQL fragment, or secret.
- A Human Identity row is locked before evaluation. First creation increments identity and security versions once and writes one allowlisted audit fact in the same database transaction. An existing result changes neither evidence nor versions.
- IAM runtime can select the two evidence tables and execute only the two fixed functions; direct insert/update/delete is denied, and immutable triggers reject later mutation.
- `portfolio-primary@iam-fixture.invalid` is established through `find → create → issue → one-shot delivery receipt → verify → ensure factor → ensure recovery`. There is no seed row, deterministic ID/code/key, alternate authenticator, direct-login path, or activation boolean.
- A second invocation and a recreated runner over the same PostgreSQL database resolve the same opaque identity and evidence while leaving one challenge, identifier, factor, and recovery row and zero W-2 outbox records.
- Fixture wiring requires both `development|test` and explicit `iam.fixtures.deterministic-identity.enabled=true`. Profile-neutral safety rejection wins for no profile, staging, production, production-like, and mixed allowed/forbidden profiles.
- Enabled fixture startup requires exactly one healthy, purpose-bound AES-256-GCM identifier capability, HMAC-SHA-256 blind-index capability, HMAC-SHA-256 challenge-digest capability, and ES256 signer capability. No signer or cryptographic fallback is installed.
- Architecture rules prevent fixture/bootstrap code from depending on JDBC, persistence adapters, authorization, or activation.
- Every allowed profile-set permutation, forbidden/unknown/mixed profile, healthy capability, and all six key-reference reuse pairs are exercised. A parameterized capability matrix covers missing and multiple beans, unhealthy results, wrong purposes, wrong algorithms, null metadata/health, thrown self-checks, invalid reference collections, within-purpose rotated reuse, and cross-purpose historical overlap for all applicable capability types.
- The complete Spring graph proves one runner, receipt, and delivery adapter and no `UserDetailsService`, `JwtEncoder`, extra `SecurityFilterChain`, controller/endpoint, generated signer/key, or fallback bean.
- PostgreSQL evidence includes empty migration, retained V3→V4 preservation/no-op, symmetric factor/recovery ID, enum, state, version, timestamp, foreign-key, composite-owner and uniqueness checks, positive persisted shapes, exact audit pairings, sequential/concurrent ensures, and six injected rollback seams.
- Runtime has SELECT/function-execute only; relay, unrelated, and public access is denied; migrator mutation is stopped by immutable triggers. Both function inputs and adapter errors remain non-revealing.
- Runtime-generated privacy canaries cover email, challenge, credential-like, private-material-like, access-value-like, and refresh-value-like inputs across protected persistence, evidence, audit/outbox/delivery, application/PostgreSQL logs, exceptions, result strings, and the no-HTTP/no-actuator fixture graph. The post-build report/artifact scan was clean and W-2 emits zero outbox rows.

## Verification

Final command:

```text
./gradlew clean test integrationTest check contractBundle --warning-mode all
```

Result: `BUILD SUCCESSFUL` with 19 actionable tasks.

- Unit tests: 139 passed.
- PostgreSQL 18 integration tests: 47 passed.
- Contract tests: 8 passed.
- Aggregate coverage: 839/887 lines = 94.6%; 421/520 branches = 81.0%.
- Checkstyle, architecture, dependency policy, secret scan, SBOM generation, Flyway clean/retained migration checks, production capability startup checks, and contract validation passed.
- Contract archive was rebuilt twice with identical SHA-256:
  `fadba94390448f36cb0def04be812683841b8887e64e3d5e049b9d359146ff6f`.
- The digest matches the accepted Work Unit 4 baseline and the ZIP integrity check reported no errors.
- No canonical contract file was changed.

## Files added or changed

- `src/main/resources/db/migration/V4__identity_factor_and_recovery_evidence.sql`
- `src/main/java/dev/distracted/iam/identity/{EvidenceMaterialGenerator,EvidenceOutcome,IdentityApplicationConfiguration,IdentityEvidence,IdentityEvidenceRejectedException,IdentityEvidenceService,SecureEvidenceMaterialGenerator}.java`
- `src/main/java/dev/distracted/iam/identity/fixture/{DeterministicIdentityFixtureConfiguration,DeterministicIdentityFixtureRunner,FixtureChallengeDelivery,FixtureException,FixtureSafetyConfiguration,OneShotChallengeReceipt}.java`
- `src/test/java/dev/distracted/iam/identity/{FixtureReceiptPresenceTest,IdentityEvidenceApiPresenceTest,IdentityEvidenceContractTest,IdentityEvidenceTest}.java`
- `src/test/java/dev/distracted/iam/identity/fixture/{DeterministicIdentityFixtureConfigurationTest,FixtureSecurityBoundaryTest}.java`
- `src/integrationTest/java/dev/distracted/iam/identity/IdentityEvidencePersistenceIntegrationTest.java`
- `src/test/java/dev/distracted/iam/architecture/ModuleBoundaryTest.java`
- `src/integrationTest/java/dev/distracted/iam/platform/persistence/WorkUnit03MigrationIntegrationTest.java`

## Deliberate remaining boundaries

- Production email/SMS delivery, provider choice, rate-limit/UX policy, and production receipt handling remain outside W-2.
- Factor/recovery execution, replacement, revocation, independence policy, and activation interpretation remain later work.
- The fixture is restart-idempotent after completion; crash-atomic and multi-instance fixture provisioning remain explicitly excluded.
- Cloud secret-manager, HSM/KMS, and operational key-custody decisions remain with the separate infrastructure work.

No commit or push was performed.
