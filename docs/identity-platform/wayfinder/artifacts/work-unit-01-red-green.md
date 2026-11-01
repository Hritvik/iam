# Work Unit 1 — Foundation RED/GREEN Evidence

Date: 2026-10-23  
Scope: IAM foundation only

## Pinned foundation

- Java toolchain: 25
- Gradle wrapper: 9.8.2
- Spring Boot: 4.1.1
- Spring Security Authorization Server: Boot-managed 7.1.1
- Testcontainers: 2.0.5
- ArchUnit: 1.5.1
- JaCoCo: 0.8.15
- Checkstyle: 14.3.0
- PostgreSQL test image: 18.0-alpine

Spring Boot dependency management supplies Spring Framework, Spring Security, Flyway, PostgreSQL JDBC, and test-library versions unless this record names an explicit foundation tool version. No production credentials, signing keys, fallback signer, or generated production token path exists.

## Cycle 1 — module boundary and fail-closed startup

Behavioral RED command:

```bash
./gradlew test \
  --tests dev.distracted.iam.architecture.ModuleBoundaryTest \
  --tests dev.distracted.iam.bootstrap.ProductionCapabilityConfigurationTest
```

Observed RED:

- `ModuleBoundaryTest.modulesDoNotReachIntoAnotherModulesPersistencePackage()` failed after detecting the deliberate identity fixture dependency on authorization persistence.
- `ProductionCapabilityConfigurationTest.productionStartupFailsWithoutExternalCryptographicCapabilities()` failed because the production context started without the required capabilities.
- Result: `2 tests completed, 2 failed`.

GREEN:

- Removed the deliberate violation and installed package rules preventing callers outside a module from reaching that module's persistence package.
- Added production-like configuration validation for explicit external capability references. Review cycle 4 later strengthened this from string presence to actual typed, self-checked capability beans.
- Added a positive context test; review cycle 4 replaced it with a real web-context test requiring both matching references and healthy typed capabilities.
- Added a foundation guard proving the runtime does not create a default `UserDetailsService` or generated authentication credential.
- The same narrow command passed.

## Cycle 2 — correlation and safe error contract

Behavioral RED command:

```bash
./gradlew test \
  --tests dev.distracted.iam.platform.http.CorrelationHttpTest \
  --tests dev.distracted.iam.platform.http.ErrorEnvelopeContractTest
```

Observed RED after correcting test-infrastructure imports/exclusions:

- valid correlation input was not echoed to the response or logging context;
- missing/invalid correlation input did not receive a bounded generated value;
- the standard error envelope type did not exist;
- result: `3 tests completed, 3 failed`, all at the intended behavioral assertions.

GREEN:

- Added a highest-precedence correlation filter with a 64-character allowlist boundary, generated 128-bit UUID value, response propagation, and MDC restoration.
- Added the closed `{error:{code,message,correlationId}}` envelope with stable-code and required-field validation.
- Added valid, missing, invalid, and MDC-restoration tests plus envelope serialization and validation negatives.
- The same narrow command passed.

## Cycle 3 — PostgreSQL/Flyway baseline

Behavioral RED command:

```bash
DOCKER_HOST=$(docker context inspect --format '{{.Endpoints.docker.Host}}') \
TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock \
./gradlew integrationTest \
  --tests dev.distracted.iam.platform.persistence.BaselineMigrationIntegrationTest
```

Observed RED:

- PostgreSQL started and Flyway executed zero migrations.
- `migratesAnEmptyPostgresqlDatabaseToTheIamBaseline()` failed at the assertion requiring exactly one baseline migration.

GREEN:

- Added the new IAM `V1__identity_platform_foundation.sql` lineage and marker assertion.
- Made the integration task honor the active Docker CLI context when `DOCKER_HOST` is absent, while preserving explicit caller configuration.
- The narrow integration command passed without manually supplied environment variables.

## Cycle 4 — security and HTTP review corrections

### Typed cryptographic capabilities

Corrective RED command:

```bash
./gradlew test --tests dev.distracted.iam.bootstrap.ProductionCapabilityConfigurationTest
```

Observed RED:

- A focused first run proved that five arbitrary nonblank strings incorrectly allowed startup.
- The expanded suite then reported `6 tests completed, 5 failed`: reference-only startup, wrong purpose/algorithm, failed self-check, reference mismatch, and real-web-context authentication assertions were not enforced.

GREEN:

- Added separate signer, identifier-encryption, and blind-index ports with capability-specific operations.
- Added bounded provider/key-reference/algorithm metadata, a typed purpose, and bounded self-check results.
- Production-like startup requires exactly one bean of each type, exact `ES256`, `AES-256-GCM`, and `HMAC-SHA-256` algorithms, matching configured references, the correct purpose, and a healthy self-check.
- No production adapter or fallback key exists. Positive tests supply explicit test-only doubles.
- A real production-like web context proves that no default user, default security chain, `JwtEncoder`, or implicit signer is synthesized. The only foundation chain is an explicit deny-all chain.
- The full narrow suite passed.

### Real HTTP error mapping

Corrective RED command:

```bash
./gradlew test \
  --tests 'dev.distracted.iam.platform.http.CorrelationHttpTest.unknownPlatformRouteUsesSafeCorrelatedErrorEnvelope' \
  --tests 'dev.distracted.iam.platform.http.CorrelationHttpTest.thrownPlatformExceptionUsesSafeCorrelatedErrorEnvelope'
```

Observed RED: `2 tests completed, 2 failed`; the 404 lacked the envelope and the thrown exception escaped as a servlet exception.

GREEN:

- Added annotation-scoped unexpected-exception handling for platform endpoints only, so future OAuth protocol endpoints are not captured by the generic handler.
- Added global handling only for framework not-found exceptions.
- Both paths now return the standard envelope with response-header/body correlation agreement.
- Response and captured-log assertions reject exception class, stack, SQL, credential, and seeded identifier leakage.

### Stronger architecture boundary

Corrective RED command:

```bash
./gradlew test --tests dev.distracted.iam.architecture.ModuleBoundaryTest
```

Observed RED: `2 tests completed, 2 failed`; deliberate fixtures proved detection of foreign `adapter.jdbc` access and direct JDBC use from a web adapter.

GREEN: removed the deliberate violations and retained rules for both `persistence`/`adapter.jdbc` ownership and web/protocol-to-JDBC isolation. The narrow suite passed.

### Build and dependency integrity

- Added the official Gradle 9.8.2 binary distribution SHA-256: `21bd5da2de49b642904077f38c0efdc7778e92b3ed0889392dca61b97e389607`.
- Verified the generated wrapper JAR SHA-256 as `3b8a25775a69158b5ad2b1d17a80a88dc7b40a352a73eb27d06c612a7ce68e98`.
- Enabled strict dependency locking in `gradle.lockfile` and SHA-256 artifact verification in `gradle/verification-metadata.xml`.
- Expanded `secretScan` to all owned source, text, configuration, migration, documentation, lock, and script files. The task first proves its own PEM, JWT, Bearer, and unquoted-assignment canaries are detected.
- JaCoCo now aggregates unit and integration execution data.
- The migration assertion now validates the current Flyway schema plus the V1 marker instead of assuming exactly one migration forever.

## Cycle 5 — immutable deny-all and controller safety review

Corrective RED command:

```bash
./gradlew test \
  --tests dev.distracted.iam.platform.http.FoundationSecurityHttpTest \
  --tests dev.distracted.iam.architecture.ModuleBoundaryTest
```

Observed RED: `5 tests completed, 3 failed`. The deliberate unmarked platform controller violated the new marker rule, while unauthenticated/authenticated requests did not receive the required correlated 401/403 envelopes.

GREEN:

- Removed the externally configurable foundation-security switch. The production deny-all chain can no longer be disabled by a runtime property.
- Correlation/error tests now use a narrowly matched, test-source-only chain for `/foundation-test/**`; no production bypass exists.
- Made the production deny-all chain the lowest-precedence fallback, allowing later explicit OAuth protocol chains to take priority without having their protocol errors rewritten.
- Added safe correlated `authentication_required` and `access_denied` entry/access-denied handlers; real security-enabled MockMvc tests prove 401 and 403 bodies match the correlation response header.
- Added an architecture rule requiring platform HTTP `@RestController` classes to opt into `@PlatformEndpoint` advice. The deliberate violating fixture was removed after RED.
- Extended web/protocol isolation to forbid dependencies on any `persistence` or `adapter.jdbc` package, including same-module access, in addition to raw JDBC APIs.
- Expanded secret candidates to PEM/key files, `.env.*`, and Dockerfile variants.
- Refreshed strict dependency locks and SHA-256 verification metadata after adding the test-only Spring Security support dependency.

## Refactor and final gates

Final clean command:

```bash
./gradlew clean test integrationTest check jacocoTestReport --warning-mode all
```

Result: `BUILD SUCCESSFUL`; 15 actionable tasks executed. This includes unit tests, PostgreSQL integration test, Checkstyle, dependency pinning policy, secret-pattern scan, SBOM generation, and JaCoCo verification/reporting.

Coverage report command:

```bash
./gradlew jacocoTestReport dependencyPolicyCheck generateSbom secretScan
```

- Unit tests: 18 passed, 0 failed/skipped
- PostgreSQL integration tests: 1 passed, 0 failed/skipped
- Aggregate line coverage: 92.4% (159 covered, 13 missed)
- Aggregate branch coverage: 80.8% (42 covered, 10 missed)
- SBOM: `build/reports/sbom/iam.cdx.json`
- The canary-self-tested repository-wide secret scan returned no findings.

## Explicit boundary and remaining work

- This work unit contains no registration, OAuth endpoint, token, refresh-family, identity, activation, or UMS behavior.
- The authorization-server dependency is present for the pinned runtime foundation only; no authorization-server business configuration is enabled.
- Production-like startup validates references, typed capability metadata/purpose/cardinality, and self-check results but does not implement or synthesize a signer or encryption key.
- Database role separation, cross-schema denial, durable domain repositories, and immutable outbox permissions are intentionally deferred to Work Unit 3. This foundation does not claim those controls.
- A vulnerability database scanner was not available locally. The completed dependency gate rejects dynamic/snapshot production dependencies and emits an inventory for a later vulnerability-scanner integration.
- The IAM directory is not currently a Git worktree, so a Git diff could not be produced. The scoped file inventory was inspected instead. No commit or push occurred.

