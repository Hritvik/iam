# W-5 implementation decisions — stable app-isolated subjects

## Scope and stopping boundary

W-5 adds the internal IAM capability that resolves one stable opaque App Subject for a trusted `(app registration, Human Identity)` pair. It persists that mapping once, returns the same public subject on every later resolution, and proves that the same Human Identity receives an unrelated subject in another registered app. The global Human Identity ID remains an IAM-internal foreign key and is never returned from the resolution result.

This item stops before access-token or refresh-token issuance, token/JWKS endpoints, DPoP, App Activation, prerequisite evaluation, onboarding events/outbox delivery, snapshots, profiles, sessions, logout, departure/reactivation, identifier/factor lifecycle, or any public/admin HTTP endpoint. W-6 and W-7 own signed tokens and their protocol bridge; W-8 owns activation and onboarding publication.

No contract change is required. Existing schemas already accept `aps_` subjects and W-5 publishes no API or event.

## Domain language and ownership

Create a focused `activation` module even though W-5 does not create an activation. App Subject is the privacy boundary on which activation will build; it does not belong to identifier, registration, or OAuth persistence.

Use immutable values and ports:

- `AppSubject` contains only the opaque `aps_...` value and has a non-revealing `toString()`.
- `AppSubjectResolutionCommand` contains `appRegistrationId`, an internal `IdentityReference`, and `CorrelationId`.
- `AppSubjectResolution` contains only `AppSubject` and a typed internal outcome `CREATED` or `EXISTING`. It has no identity ID, registration graph, profile state, activation state, or arbitrary attributes.
- `AppSubjectResolver.resolve(command)` is the application use case.
- `AppSubjectRepository.resolve(appId, identityId, candidateSubject, auditId, correlationId)` is the persistence port and returns `CREATED`, `EXISTING`, `RETRY_COLLISION`, or `REJECTED` plus a subject only for the first two outcomes.
- `AppSubjectMaterialGenerator` generates App Subject and audit identifiers. Production uses `SecureRandom`; tests may inject a deterministic sequence without adding a profile-specific production bean.

The application retries only `RETRY_COLLISION`, with a small fixed maximum of three fresh candidates. Exhaustion and `REJECTED` become the same safe internal resolution failure. There is no caller-selected subject, lookup-by-subject API, list operation, cross-app query, or raw repository row exposure.

The future W-7 orchestration calls this port only with the trusted app/identity tuple returned by successful atomic authorization-code consumption. W-5 tests may construct that typed command directly; W-5 must not open `/oauth2/token` or introduce a validation-only code endpoint.

## Subject construction and entropy

Generate exactly 18 random bytes from a CSPRNG and encode them with unpadded base64url after the literal `aps_` prefix. The production form is therefore `aps_` plus 24 URL-safe characters and carries 144 bits of entropy, exceeding the settled 128-bit minimum while remaining inside the published `^aps_[A-Za-z0-9_-]{22,128}$` shape.

Randomness is not derived from, seeded by, encrypted from, hashed from, or otherwise a function of Human Identity ID, app ID, email, phone, authorization request, correlation ID, time, sequence, database key, or signing/encryption material. There is no subject cryptographic key, key version, rotation ring, or reversible subject representation. Persistence, not deterministic derivation, supplies stability.

Tests use an injected byte source to prove exact prefix/encoding/length and retry behavior. They do not claim that a finite sample statistically proves CSPRNG quality; production construction and the absence of derivation inputs are architecture/security assertions backed by source inspection and tests that feed identity-shaped canaries and observe no structural inclusion.

## V7 persistence model

Add a forward-only `V7__app_subject.sql` migration with:

```text
app_subject
  app_registration_id  text        not null FK app_registration on delete restrict
  human_identity_id    text        not null FK human_identity on delete restrict
  app_subject          text        not null
  version              bigint      not null default 1
  created_at           timestamptz not null default transaction_timestamp()
  primary key (app_registration_id, human_identity_id)
  unique (app_registration_id, app_subject)
  unique (app_subject)
  check app_subject matches exactly ^aps_[A-Za-z0-9_-]{24}$
  check version = 1
```

The pair primary key is the stability invariant. App-scoped subject uniqueness is the settled contract invariant. A defense-in-depth global uniqueness constraint on the random public value additionally makes accidental or deliberately injected equality across apps impossible; it does not change the public semantic key, grant a lookup surface, or permit an app to observe the index. Any candidate collision—within or across apps—returns `RETRY_COLLISION`, and the application generates a fresh value. This makes “different app, different subject” deterministic under adversarial tests rather than merely overwhelmingly probable.

The mapping is immutable in W-5: no state, `updated_at`, soft-delete, rotation, replacement, or version-advance function exists. App suspension/departure must not change the subject. Later identity erasure/merge policy requires an explicit expand/migrate/retire decision and must not silently reassign a subject. Foreign keys use `ON DELETE RESTRICT` so deletion cannot accidentally break stability or orphan activation/onboarding history.

## Database authority and concurrency

Create one parameterized `SECURITY DEFINER` function, owned by `iam_migrator`, with `SET search_path = pg_catalog, public`:

```text
resolve_app_subject(
  p_app_registration_id,
  p_human_identity_id,
  p_candidate_app_subject,
  p_audit_id,
  p_correlation_id
) -> (result, app_subject, created_at, version)
```

The function explicitly rejects every NULL and malformed argument before touching state. It verifies the Human Identity exists and is `ACTIVE`. It verifies that the app is a coherent registered app by requiring the app row plus its client, resource, and product-security-policy rows; it does not accept an arbitrary app-shaped string. It does not require Dutch's no-argument `canonical_registration()` because that W-3 function intentionally represents the sole pinned Dutch authorization graph and would prevent future registered apps from using the portfolio capability. Registration mutation remains restricted to the migrator/reconciler authorities established by W-3.

Resolution performs `INSERT ... ON CONFLICT DO NOTHING`, then selects by `(app_registration_id, human_identity_id)` in a subsequent PL/pgSQL statement. This is intentional: after a conflicting concurrent insert waits, the subsequent statement receives a new Read Committed snapshot and sees the committed winner. Outcomes are:

- inserted pair: write exactly one `APP_SUBJECT_ALLOCATED` audit fact and return `CREATED` with the candidate;
- pair already exists: return `EXISTING` with the stored winner and write no second fact;
- candidate collided with any existing public subject and no pair exists: return `RETRY_COLLISION` with no subject and no audit;
- missing/inactive identity, incomplete/missing app, malformed input, or invariant failure: return/raise a closed `REJECTED` outcome with no protected detail.

The insert and creation audit fact commit in one local transaction. Failure before, between, or after them rolls back both. No JVM lock, preflight existence read, serializable isolation, network call, or outbox write is used. Database uniqueness supplies the single winner across threads, application instances, and restarts.

Extend the closed audit allowlist with `APP_SUBJECT_ALLOCATED` and subject kind `APP_SUBJECT`. The fact's subject ID is the globally collision-protected opaque App Subject; it carries `SUCCEEDED`, correlation ID, and database timestamp. The existing audit schema has no app-registration column, and W-5 must not overload another field or add a free-form detail map to smuggle it in. The fact contains no Human Identity ID, identifier, authorization artifact, token, profile/activation data, candidate collision value, or arbitrary details. Add a partial unique index enforcing one `APP_SUBJECT_ALLOCATED` fact per subject. Existing audit immutability remains in force.

## Database privileges

`iam_migrator` owns `app_subject` and `resolve_app_subject(...)`. Revoke all table/function access from PUBLIC. Grant `iam_runtime` EXECUTE on the function only; do not grant it direct `SELECT`, `INSERT`, `UPDATE`, `DELETE`, or `TRUNCATE` on `app_subject`. The function uses fully qualified object names.

Do not grant App Subject access to `iam_registration_reconciler`, `iam_outbox_relay`, PUBLIC, or an unrelated role. Existing broader privileges on identity/registration tables are not expanded. A later activation/snapshot function may read the mapping through its own security-definer boundary; W-5 does not add that read surface.

Migration acceptance verifies prerequisite-role failure, object owners, function volatility/security-definer/fixed search path, PUBLIC revoke, exact runtime EXECUTE, denied table operations for runtime/reconciler/relay/unrelated roles, and migrator authority.

## Second-app isolation proof

Production V7 does not add a Midas, Jarvis, wildcard, or generic registration and does not alter W-3's pinned Dutch manifest/digest. The isolation integration fixture uses the migrator connection to insert a complete second **test-only** normalized registration graph (app, client, resource, policy, and required child rows) into the disposable PostgreSQL database. It is not a classpath manifest, startup reconciler input, migration row, or runtime API.

Against that fixture, resolve the same Human Identity for Dutch and the second app and prove:

- each pair remains stable across repetition and full application-context restart;
- the two returned subjects differ;
- neither app-scoped result can query or enumerate the other mapping because W-5 exposes no subject lookup/list surface and runtime lacks table access;
- concurrent first resolution in each app has one independent winner;
- forced candidate collisions within or across apps retry and never create a shared public value or a globally queryable application surface.

This proves the portfolio model without pretending Midas/Jarvis integration is delivered or weakening W-3's one published Dutch registration.

## Privacy, errors, and observability

App Subjects are pseudonymous identifiers, not secrets and not PII-free in the sense of being harmless. Treat them as allowlisted only at the later app-specific token/event boundary. W-5 has no external response, event, contract, or endpoint.

Never log, metric-label, trace-attribute, or exception-render the Human Identity ID, App Subject, candidate, audit ID, or command object. Operational telemetry uses bounded reasons only: `created`, `existing`, `collision_retry`, `rejected`, `retry_exhausted`, and a correlation ID where the platform's existing rules permit it. Metrics use bounded outcome tags and never app/identity/subject values. Domain and persistence objects have non-revealing `toString()` implementations; SQL remains parameterized; exception translation emits fixed messages without SQL/constraint/row data.

Canary tests capture returned objects, exception text, structured logs, metric identifiers/tags, audit rows, and outbox rows. They prove Human Identity IDs and seeded raw email/phone/credential/code/token/session values are absent everywhere outside the internal command/database FK. They also prove no W-5 outbox event exists. The App Subject may appear only in the typed internal successful result, the `app_subject` row, and its IAM-internal allocation audit fact.

## TDD acceptance matrix

Record observed behavioral RED before each production increment and a final GREEN/refactor artifact.

### Unit and architecture

1. Generator emits exactly 18 CSPRNG bytes as a 24-character unpadded base64url value after `aps_`; malformed/padded/short/long/non-URL-safe values are rejected.
2. Repeated resolution returns the existing value; collision triggers a bounded fresh-candidate retry; retry exhaustion is safe and non-revealing.
3. Resolution values are immutable, defensively validated, have safe `toString()`, and expose no global identity in the result.
4. Production generator has no deterministic/profile fallback and accepts no identity/app/time/key input. The deterministic identity fixture does not precompute or authenticate an App Subject.
5. Architecture rules keep JDBC under `activation.adapter.jdbc`, keep Spring/JDBC types out of domain values, and prohibit token, activation, outbox, HTTP, and public-contract additions in W-5.

### PostgreSQL 18 integration

1. Clean V1–V7 and V1–V6→V7 upgrades are equivalent and preserve existing state; rerun is a no-op; missing prerequisite roles fail.
2. Literal matrices exercise every V7 NOT NULL, check, primary-key, unique, and foreign-key constraint, plus `ON DELETE RESTRICT` and exact function metadata/grants/table-operation denials.
3. First resolution writes one mapping plus one allocation audit atomically; injected failures before mapping, between mapping/audit, and after audit leave neither partial effect.
4. Repetition returns the same subject and no extra audit. Barrier-synchronized concurrent first resolution over separate connections returns one identical winner to every caller and stores one row/fact.
5. Forced same-app and cross-app subject collisions return retry without leaking the other identity/subject relation; application retry succeeds with a fresh candidate. Same identity across Dutch and a complete test-only second app receives different stable subjects.
6. Missing/inactive identity, missing/incomplete app, malformed IDs, NULL arguments, and unauthorized direct/execute operations fail closed without rows.
7. Close and recreate a full Spring application context against the same database and prove stability. Existing mappings survive generator changes because no derivation is repeated.

### Privacy and contract stability

1. Canary-scan application results, errors, captured logs, metric names/tags, trace attributes if configured, audit/outbox rows, and serialized diagnostic forms for global identity, raw identifiers, credentials, codes/tokens, and cross-app subject leakage.
2. Assert the only allowed App Subject locations in W-5 are its mapping row, IAM-internal allocation audit, and typed successful internal result.
3. Run contract validation/bundle and prove its digest is unchanged. No `iam.identity.verified.v1`, onboarding event, snapshot, token, or new HTTP schema is added.

### Verification gate

Run clean `test`, PostgreSQL 18 `integrationTest`, `contractTest`, `check`, `contractBundle`, 80%+ line and branch coverage, dependency policy/SBOM, secret scan, migration clean/upgrade/restart tests, conflict-marker/diff inspection, and independent correctness/database and security reviews. No unresolved critical, high, or medium finding is acceptable.

## Explicit exclusions and later dependencies

W-5 deliberately excludes:

- access/refresh/ID token issuance, signed or unsigned tokens, token/JWKS/UserInfo/introspection/revocation endpoints, DPoP, and Spring Authorization Server token services;
- authorization-code validation or consumption changes beyond using its trusted result in a later work item;
- App Activation rows/states/prerequisite evaluation, onboarding versions/events, transactional outbox, relay, snapshots, UMS, profiles, or member mappings;
- public/internal HTTP or administrative subject lookup/list/search endpoints;
- Midas, Jarvis, or other production registrations and product-owned profiles;
- subject rotation, merge, split, reassignment, erasure, departure, or reactivation behavior;
- deterministic/derived subjects, subject encryption/digests/key rotation, or fallback randomness;
- cloud/KMS/broker/provider selection, commit, push, publication, or deployment.

There is no human design blocker. W-7 must compose successful code consumption, App Subject resolution, DPoP validation, and signed token issuance without losing the consumed authorization on a later failure; that transaction/workflow boundary is intentionally decided by W-7 rather than invented here.
