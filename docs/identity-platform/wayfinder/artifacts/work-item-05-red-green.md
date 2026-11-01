# W-5 RED→GREEN evidence — stable app-isolated subjects

## Scope

Implemented the IAM-internal App Subject allocation capability only. W-5 adds no HTTP endpoint, token issuance,
activation state, onboarding event, outbox write, production app registration, or contract change.

## Observed REDs

1. `AppSubjectResolverTest` initially failed compilation because the App Subject value, command, result, resolver,
   material generator, repository port, and safe failure did not exist.
2. `AppSubjectPersistenceIntegrationTest` initially failed because `app_subject` and
   `resolve_app_subject(...)` did not exist.
3. The JDBC-adapter acceptance test initially failed compilation because `JdbcAppSubjectRepository` did not exist.
4. The first full clean gate exposed existing fixture cleanup and migration-count assumptions made obsolete by V7;
   the failures named the new `app_subject` foreign key and the additional migration explicitly.
5. The first full application-context restart test failed because a non-web context could not construct the existing
   servlet security chain; the test was corrected to restart the real servlet application context on an ephemeral port.
6. The first post-implementation coverage gate failed at 79% branch coverage; boundary and closed-outcome tests were
   added before the gate was rerun.
7. The independent database review identified a check-then-act eligibility race. Deterministic overlapping-transaction
   tests held an identity disable and registration-child deletion open while resolution waited; V7 was changed to lock
   the active identity, normalized registration parents, and required child rows through mapping and audit insertion.

## GREEN behavior

- `SecureAppSubjectMaterialGenerator` uses `SecureRandom`, exactly 18 bytes, unpadded base64url, and the `aps_` prefix.
- The public value is validated as exactly 24 URL-safe characters after the prefix and is never derived from identity,
  app, time, correlation, or cryptographic-key inputs.
- `AppSubjectResolver` returns only an opaque App Subject and `CREATED`/`EXISTING`, retries only collisions, and fails
  with one fixed non-revealing error after three attempts or a database rejection.
- V7 owns one immutable mapping per `(app_registration_id, human_identity_id)`, app-scoped and global subject
  uniqueness, restrictive foreign keys, and one immutable `APP_SUBJECT_ALLOCATED` audit fact.
- The security-definer function validates every argument, requires an active identity and a complete normalized app
  graph, uses database uniqueness for concurrent insert-or-return, and exposes only `CREATED`, `EXISTING`,
  `RETRY_COLLISION`, or `REJECTED`.
- Runtime receives function execution only. Runtime, relay, registration reconciler, PUBLIC, and unrelated services
  receive no direct mapping-table access; only runtime may execute the function.
- Integration tests cover repetition, barrier-synchronized concurrency, same-app/global collision handling, a complete
  test-only second app, cross-app subject separation, inactive/missing/incomplete inputs, all five NULL function
  arguments, audit rollback, immutability, full application-context restart, and clean versus V6→V7 migration parity.
- Overlapping identity-disable and registration-mutation transactions prove allocation waits for eligibility authority,
  then rejects without a mapping or audit after the mutation commits and without deadlock.
- Literal privilege checks cover object/function ownership, exact execution authority, PUBLIC revocation, migrator
  authority, and every table operation for runtime, reconciler, relay, unrelated, and PUBLIC authority. Constraint tests
  exercise all mapping NOT NULL columns, shape/version checks, primary/global uniqueness, both foreign keys, allocation
  audit uniqueness, immutability, and restrictive parent deletion.
- Function privilege evidence enumerates the literal EXECUTE ACL as exactly `iam_migrator` and `iam_runtime`, with
  explicit denials for PUBLIC, registration reconciler, relay, and an unrelated service role.
- Injected failures before mapping insertion, after mapping but before audit, and after audit insertion prove the
  statement leaves neither partial mapping nor partial audit.
- A populated V6 database retains its identity and audit state after V7. Both test apps allocate independently and
  return different stable subjects after a full application-context restart.
- No W-5 outbox or external response exists. Identity IDs remain confined to the typed internal command and database
  foreign key; result and exception rendering are non-revealing.

## Verification

The final clean gate command is:

```text
./gradlew clean test integrationTest contractTest check contractBundle dependencyPolicyCheck generateSbom secretScan
```

It completed `BUILD SUCCESSFUL` with 247 unit tests, 267 PostgreSQL 18 integration tests, and 8 contract tests.
JaCoCo reported 93.92% line and 80.90% branch coverage. Checkstyle, dependency policy, SBOM generation, secret scan,
contract validation/bundling, and conflict-marker inspection passed.

The contract archive SHA-256 remains
`fadba94390448f36cb0def04be812683841b8887e64e3d5e049b9d359146ff6f`.

## Deliberate limits

W-5 does not claim statistical proof of CSPRNG quality or exported trace attributes: the activation module has no
logging, metrics, tracing, HTTP, authorization/token, or outbox dependency, while integration coverage scans the
configured application logs, metric identifiers/tags, internal result diagnostics, allocation audit, and empty outbox.
Identity merge/erasure semantics, subject rotation, and production registration of Midas, Jarvis, or another portfolio
app remain governed by the decision record and later work items.
