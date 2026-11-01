# W-3 RED/GREEN evidence — pinned Dutch registration

Date: 2026-10-24  
Work item: W-3 — Load and expose the pinned Dutch registration

## TDD loops

1. **Canonical source RED:** `ClasspathPinnedRegistrationSourceTest` failed compilation because no source port or adapter existed. **GREEN:** bounded defensive-copy classpath source backed only by the packaged canonical contract.
2. **Strict validation RED:** `RegistrationManifestValidatorTest` failed compilation because no validator or immutable manifest existed. **GREEN:** duplicate-key rejection, Draft 2020-12 schema validation with format assertions and a bundled-only schema mapping, unknown-field rejection, immutable typed values, pinned tuple checks, semantic redirect checks, canonical JSON, and SHA-256 fingerprinting.
3. **Persistence RED:** `RegistrationPersistenceIntegrationTest` failed compilation before the registry and V5 existed, then failed at real Flyway execution on invalid multi-table ownership syntax, and then at the function signature's `smallint` boundary. **GREEN:** normalized V5 graph, restrictive constraints and FKs, migrator ownership, revoked PUBLIC access, runtime SELECT-only lookup, a distinct reconciler role with function-only authority, parameterized lookups, idempotency, drift preservation, and exact tuple reads on PostgreSQL 18.
4. **Metadata RED:** metadata unit and HTTP tests failed compilation before the port, representations, controller, exception mapping, and exact security chain existed. The first HTTP run also exposed incorrect assumptions about framework cache-header order and HEAD body suppression. **GREEN:** closed representations derived from the registry, strict issuer parsing, explicit HEAD handling, exact public paths, safe 503 mapping, required headers, and foundation denial for other paths/methods.
5. **Regression RED:** retained V1/V3 migration tests correctly failed their old migration-count assertions after additive V5. **GREEN:** expectations now cover V2–V5 and retained data remains unchanged.
6. **Coverage RED:** the first clean gate reported 73% branch coverage and the schema-validation addition later reported 78–79%. **GREEN:** negative boundary matrices and simplified exact-tuple comparisons raised aggregate branch coverage above the unchanged 80% gate.
7. **Independent-review trust-boundary RED:** a dedicated reconciler login could not initially resolve the function, normal runtime retained EXECUTE, and arbitrary input was not pinned at the database authority boundary. **GREEN:** externally provisioned `iam_registration_reconciler`, explicit schema usage plus function-only EXECUTE, runtime EXECUTE revocation, and a migration-owned exact tuple/fingerprint allowlist. Canonical input succeeds; arbitrary app or fingerprint input is rejected before mutation.
8. **Independent-review integration RED:** HTTP tests originally used a stub metadata source and persistence tests shared graph state. **GREEN:** isolated graph setup, a real PostgreSQL-backed Spring context, startup reconciliation through the dedicated role, runtime-only metadata lookup, GET/HEAD/method/near-miss/query/absence/ambiguity matrices, safe retryable errors, concurrency, persisted drift, rollback, role absence, and privilege-matrix tests.
9. **Final-review canonical-read RED:** runtime lookup could still construct metadata from drifted rows. **GREEN:** a read-only security-definer authority function now returns the registration only when exactly one complete graph and fingerprint match the private allowlist. Fourteen scalar/child deletion/addition mutations return safe `503 metadata_unavailable` on both real endpoints without a partial body.
10. **Final-review wiring/restart RED:** reconciler connectivity previously relied on a test-supplied bean and an ordering-sensitive condition. **GREEN:** mandatory typed reconciler JDBC properties, distinct-credential checks, live mutually exclusive PostgreSQL role-membership checks, no runtime fallback, real full-context startup, full application restart against retained state, clean second-database convergence, and actual database-outage HTTP evidence.
11. **Final correctness race/authority RED:** canonical verification and graph loading were separate database operations, leaving a check/use window in which a concurrently changed graph could be served. **GREEN:** every registration lookup now calls one read-only security-definer PostgreSQL statement that verifies and returns the entire canonical JSON graph from a single statement snapshot. A latch-coordinated transaction holds a drift mutation uncommitted while the runtime read executes, proving it returns the prior complete canonical snapshot; after commit the same read is unavailable, never mixed or drifted. The final matrix literally exercises every public registration-graph `NOT NULL` column (including timestamps), parent primary-key duplicate, app-client/resource and audience uniqueness, value/length/identifier/audience/policy/grant/PKCE/evidence check, foreign key, and restricted parent deletion. The private migration-owned allowlist is instead covered by exhaustive role/operation denial and canonical-authority tests. The matrix also covers every SELECT/INSERT/UPDATE/DELETE/TRUNCATE combination for runtime, reconciler, relay, unrelated, PUBLIC, and migrator across every V5 table, both functions' execution/metadata, and complete GET/HEAD header parity for both public endpoints.

## Clean verification

Command:

```text
./gradlew clean test integrationTest check contractBundle --warning-mode all
```

Result: `BUILD SUCCESSFUL` (19 actionable tasks).

- Unit tests: 190
- PostgreSQL 18 integration tests: 174
- Contract tests: 8
- Line coverage: 94.55%
- Branch coverage: 80.37%
- Checkstyle: passed for main, test, integration, and contract source sets
- Dependency policy and lock verification: passed
- SBOM generation: passed
- Secret scan: passed
- Flyway clean/retained migration paths: passed
- Contract ZIP integrity: passed
- Contract bundle SHA-256: `fadba94390448f36cb0def04be812683841b8887e64e3d5e049b9d359146ff6f` (unchanged)

## Security and scope notes

- Reconciliation is disabled by default and requires explicit `iam.registration.dutch-development.enabled=true`, an exclusively `development`/`test` active-profile set, `iam.environment=development`, a strict HTTPS issuer, the packaged valid manifest, and a working database.
- Runtime receives read-only table access plus EXECUTE only on `canonical_registration()` and cannot execute reconciliation. A separate externally provisioned NOLOGIN reconciler role receives schema usage and EXECUTE only on `reconcile_pinned_registration(...)`; it receives no table read or mutation rights. Both security-definer functions fix their search path; reconciliation accepts scalar/array parameters only and first matches every value plus the canonical fingerprint against its migration-owned allowlist.
- Runtime metadata reads pass through a second read-only security-definer function that verifies exact graph cardinality, all scalars, fingerprint, and every child set against the private allowlist while constructing the complete immutable graph in that same database statement and snapshot.
- Published metadata contains registration policy outcomes only; it contains no identifier, identity ID, credential, secret, code, token, session, or private-key material.
- W-3 does not enable authorization requests, codes, tokens, refresh grants, OIDC discovery, ID tokens, dynamic registration, or JWKS publication.

## Remaining integration boundary

The authorization-server metadata intentionally advertises the future contracted authorization, token, and JWKS URIs, while the foundation chain continues to deny those paths until their owning work items. Resource-origin publication/routing of RFC 9728 metadata remains a Dutch/Gateway deployment concern outside W-3 ownership.
