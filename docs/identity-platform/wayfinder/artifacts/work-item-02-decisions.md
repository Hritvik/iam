# Work Item 02 Decision Record: Explicitly Gated Deterministic Identity

**Status:** ready for TDD implementation  
**Scope:** deterministic development/test identity orchestration plus the minimum normal-model factor and recovery evidence  
**Depends on:** accepted W-1 / Work Unit 4 protected-identifier behavior, D-8, and D-10

## Boundary and completion invariant

W-2 establishes one repeatable logical Human Identity using the same identity, identifier-challenge, verification, factor, recovery, PostgreSQL, audit, and cryptographic ports that later application flows use. The deterministic property is the reserved identifier and the converged persisted state; opaque IDs, challenge codes, nonces, and cryptographic material remain random.

The fixture is an internal startup runner, not an HTTP endpoint, authentication provider, security filter, user-details service, token issuer, or alternate persistence adapter. It may orchestrate application ports but cannot use `JdbcTemplate`, repositories, Flyway callbacks, SQL seed data, test-container initialization, or direct table writes. A completed run leaves exactly one verified reserved email, one usable email-OTP factor, and one verified-email recovery method on the resolved identity. It produces no App Subject, activation, authorization artifact, token, outbox event, or cross-service fact.

W-2 adds only the evidence needed by the later strict activation policy. Factor authentication ceremonies, recovery execution, replacement, suspension, revocation, step-up policy, independence between factor and recovery channels, passkeys, passwords, TOTP, recovery codes, and provider delivery are later-slice concerns. Their absence is explicit and must not be disguised with placeholder behavior.

## Minimum normal factor and recovery model

The scoped portfolio journey uses the already verified email in two explicit roles:

- an `EMAIL_OTP` authentication factor in state `ACTIVE`, bound to that verified-email row; and
- a `VERIFIED_EMAIL` recovery method in state `ACTIVE`, bound to the same verified-email row.

These are normal IAM facts, not rows marked as fixture data. They are sufficient for D-10 because activation can separately prove a verified identifier, an active usable factor, and an active recovery path. The current milestone does not require those two paths to be independent. A later Product Security Policy may require independent factors or recovery channels without changing what these rows mean.

An `EMAIL_OTP` factor stores no OTP, reusable credential, delivery address, or secret. It means IAM may authenticate this identity by issuing a fresh, bounded possession challenge to its bound verified email through the normal challenge/delivery path. A `VERIFIED_EMAIL` recovery method similarly stores only the binding and eligibility fact; it is not a completed recovery ceremony.

Expose profile-neutral typed application operations in `identity`, with equivalent names if repository conventions demand them:

- `EnsureEmailOtpFactor(identityReference, correlationId)` returns an opaque factor reference and `CREATED|EXISTING`;
- `EnsureVerifiedEmailRecovery(identityReference, correlationId)` returns an opaque recovery reference and `CREATED|EXISTING`;
- each operation resolves the identity's verified `EMAIL` internally, validates ownership and active state, and reveals no identifier or persistence entity;
- a first creation increments Human Identity `security_version` and aggregate `version` once and appends its allowlisted audit fact in the same transaction;
- an idempotent existing result changes no version and creates no second audit fact.

The fixture calls both operations. It does not receive a special `markPrerequisitesSatisfied` operation and cannot write activation-oriented booleans.

## V4 persistence decision

Persisted evidence is necessary. Computing factor/recovery readiness from the fixture profile or from the mere presence of a verified identifier would create a production-visible bypass and would make later activation unable to distinguish its three prerequisites. Flyway V4 therefore adds the following focused tables.

### `authentication_factor`

- `factor_id text primary key`, matching `^fac_[A-Za-z0-9_-]{22,128}$`;
- `identity_id text not null references human_identity(identity_id) on delete restrict`;
- `verified_identifier_id text not null references verified_identifier(identifier_id) on delete restrict`;
- `factor_type text not null`, closed in V4 to `EMAIL_OTP`;
- `state text not null`, closed in V4 to `ACTIVE`;
- `version bigint not null default 1 check (version = 1)`;
- `created_at` and `updated_at timestamptz not null`, supplied by PostgreSQL `transaction_timestamp()`;
- unique `(identity_id, factor_type)` and unique `(verified_identifier_id, factor_type)`.

### `recovery_method`

- `recovery_method_id text primary key`, matching `^rcv_[A-Za-z0-9_-]{22,128}$`;
- `identity_id text not null references human_identity(identity_id) on delete restrict`;
- `verified_identifier_id text not null references verified_identifier(identifier_id) on delete restrict`;
- `recovery_type text not null`, closed in V4 to `VERIFIED_EMAIL`;
- `state text not null`, closed in V4 to `ACTIVE`;
- `version bigint not null default 1 check (version = 1)`;
- `created_at` and `updated_at timestamptz not null`, supplied by PostgreSQL `transaction_timestamp()`;
- unique `(identity_id, recovery_type)` and unique `(verified_identifier_id, recovery_type)`.

V4 creates fixed-SQL, fixed-`search_path`, `SECURITY DEFINER` functions for the two ensure operations. Each function locks the Human Identity first, requires it to be `ACTIVE`, selects an existing verified `EMAIL` belonging to that identity, returns an existing evidence row unchanged when present, or inserts the supplied CSPRNG opaque ID and increments the identity/security versions exactly once. It accepts no identifier value, state, type, timestamp, SQL fragment, or secret from the caller. A mismatched identity/identifier, missing verified email, stale version, or uniqueness race produces a typed safe outcome; raw PostgreSQL errors do not escape the adapter.

Runtime receives table `SELECT` and execute permission on those functions only. It receives no factor/recovery `INSERT`, `UPDATE`, `DELETE`, or `TRUNCATE`. Public receives no access. The migrator owns the objects. V4 rejects direct update/delete of these append-only milestone facts; a later lifecycle migration must deliberately introduce bounded transitions and grants.

Extend the closed audit model with only:

- `AUTHENTICATION_FACTOR_REGISTERED` / subject kind `AUTHENTICATION_FACTOR` / `fac_...` subject;
- `RECOVERY_METHOD_REGISTERED` / subject kind `RECOVERY_METHOD` / `rcv_...` subject.

Both use `SUCCEEDED`, the command correlation ID, no event ID, no reason/details map, and database transaction time. No W-2 operation writes `outbox_event` or `outbox_delivery`.

Use a focused CSPRNG-backed evidence material generator for `fac_` and `rcv_` IDs rather than weakening or making the existing identity generator deterministic. Domain records defensively copy protected data where applicable and have non-revealing `toString()` behavior.

## Fixture orchestration

The reserved logical fixture is:

- fixture name: `portfolio-primary`;
- identifier type: `EMAIL`;
- submitted value: `portfolio-primary@iam-fixture.invalid`;
- normalized value: the same ASCII value.

`.invalid` is deliberately non-routable. The address remains PII-class data for handling and testing: it may exist transiently at the application boundary and encrypted in the identifier/challenge tables, but never in logs, exceptions, audit, events, HTTP, metrics, bean names, or test display names.

The runner executes this algorithm through application ports:

1. Find the identity by the reserved email using `FindIdentityByIdentifier`.
2. If present, use the returned opaque identity reference and skip challenge creation.
3. If absent, call `CreateIdentity`, then `IssueIdentifierChallenge` with the reserved email, a ten-minute TTL, and three attempts.
4. Receive the newly generated plaintext challenge only from the fixture delivery receipt described below and call `VerifyIdentifierChallenge`.
5. If promotion reports the bounded identifier-conflict result, re-run `FindIdentityByIdentifier` and use the winner. Any other failure aborts startup with a stable fixture error code and no sensitive cause/message.
6. Call both normal evidence ensure operations. Treat `CREATED` and `EXISTING` as success.
7. Return only an internal completion result containing the opaque identity reference; emit at most the safe event name, result code, and correlation ID.

After a successful setup, repeated calls and a recreated application context converge without issuing another challenge or adding identity evidence. Concurrent first-ever fixture bootstraps are not a supported deployment mode in W-2: this development/test startup fixture runs once in one local test process. The underlying identifier and evidence uniqueness rules still ensure one verified identifier and one evidence row if a race is deliberately exercised; a losing pre-verification identity may remain and is not claimed as production provisioning semantics. Multi-instance fixture coordination would be test infrastructure, not an identity guarantee, and is excluded.

W-2 proves restart idempotency after a completed run. It does not claim a crash-atomic multi-transaction bootstrap. A crash between challenge delivery and verification may leave normal resumable challenge/identity state; challenge resume and cleanup policy belong with production verification delivery. Tests must not hide this boundary with database cleanup inside the fixture.

## Plaintext challenge delivery seam

A test-only delivery receipt is necessary because the challenge generator must remain random and the fixture must prove the real verification path. Add a development/test fixture adapter implementing `ChallengeDeliveryPort` plus a narrow internal one-shot receipt interface:

- `deliver(challengeId, SecretChallengeCode)` stores the code only in bounded in-process memory;
- `take(challengeId)` atomically removes and returns the exact code once;
- duplicate delivery IDs, an unknown ID, overflow, or a second take fail with stable safe codes;
- the entry is removed after verification and the store is cleared on failed setup/context shutdown;
- code values have no logging, serialization, inspection, endpoint, actuator exposure, or revealing `toString()` path.

This adapter is present only when the complete fixture gate is open. It is a delivery adapter, not an authenticator: verification still invokes `VerifyIdentifierChallenge` and the stored HMAC, expiry, attempts, terminal-state, uniqueness, and transaction rules all apply. Production-like graphs can never contain the adapter. The fixture must not replace the CSPRNG generator with a known code, read `challenge_digest`, decrypt candidate data, or call a repository to discover the answer.

Java strings cannot be reliably zeroized. Keep the existing `SecretChallengeCode` boundary for W-2, minimize its lifetime, remove it immediately after use, and prevent retention/serialization. A mutable secret container can be evaluated with a future delivery implementation; it is not license to persist or log the current value.

## Dual gating and startup rejection

Use one property with a secure default:

`iam.fixtures.deterministic-identity.enabled=false`

Opening the fixture requires both:

1. an active `development` or `test` Spring profile; and
2. the property set explicitly to `true`.

The fixture configuration is guarded by both `@Profile("development | test")` and `@ConditionalOnProperty(..., havingValue="true")`. A separate profile-neutral safety guard reads the raw opt-in early and rejects startup when it is true without an allowed profile or when any of `staging`, `production`, or `production-like` is also active. Thus mixed profiles such as `development,production-like` fail instead of allowing the development branch to win. Unknown environment names do not make the fixture eligible.

The fixture-specific source package may contain the runner, properties, safety guard, receipt interface, and in-memory delivery adapter. The factor/recovery model and application services remain profile-neutral in `identity`. No fixture class is referenced from a production-neutral controller, security configuration, token code, or activation policy.

An enabled fixture fails startup if any required normal application port, PostgreSQL connection/migration, encryption keyring, blind-index keyring, challenge-digest keyring, or non-production signer capability is absent or unhealthy. The signer is checked now so the deterministic portfolio journey cannot later acquire an unsigned fallback, although W-2 neither signs nor issues a token. The check uses the existing typed `TokenSignerCapability` metadata/self-check contract and requires the approved asymmetric algorithm; it does not install `JwtEncoder`, a token endpoint, or a signer substitute.

## Non-production cryptographic and signing injection

W-2 adds no key bytes, credentials, private-key PEM, deterministic nonce, shared development password, or fallback key to source, `application.yaml`, fixtures, migrations, Docker files, reports, or generated bundles.

The fixture graph consumes already constructed typed capabilities:

- `StructuredIdentifierEncryptionCapability`;
- `VersionedBlindIndexCapability`;
- `ChallengeDigestCapability`;
- `TokenSignerCapability`.

Unit and integration tests inject purpose-separated random key material generated for that test context and a real test-only ES256 signer or a metadata/self-checking test double where signing is not exercised. Development launch wiring must obtain non-production material from environment/secret injection and construct the same typed capabilities with explicit key references and versions. Selecting a secret manager, HSM/KMS, cloud provider, production key location, or operational rotation schedule is outside W-2. Production-like profiles continue to use `ProductionCryptographicCapabilityConfiguration` and fail closed without externally supplied references and exactly one healthy capability of each required purpose.

No fixture property contains secret material. Binding secrets into generic Spring configuration merely to make local startup convenient is not part of this item; an environment-specific launcher may supply beans without changing the fixture contract.

## Current code touch points

Implementation should remain inside these boundaries:

- evolve `identity/IdentityService.java` only as needed to expose safe identifier-conflict behavior or verified-email evidence resolution; preserve its PostgreSQL-clock, protected-value, and non-enumerating contracts;
- keep `identity/ChallengeDeliveryPort.java` as the production-facing delivery boundary; add the one-shot receipt as a separate fixture-only interface rather than adding a plaintext-return method to the production port;
- keep `identity/SecureIdentityMaterialGenerator.java` random; add a focused evidence-ID generator instead of deterministic IDs;
- add profile-neutral factor/recovery commands, results, records, repositories/adapters, and wiring under `identity`;
- add fixture-only wiring under an explicit `identity.fixture` or `bootstrap.fixture` package;
- add `V4__identity_factor_and_recovery_evidence.sql` after the accepted V3 migration; never edit V1–V3;
- extend `audit_fact` allowlists through V4 without adding free-form fields;
- extend `ModuleBoundaryTest` so fixture/bootstrap code can depend on identity application ports but not JDBC, persistence adapters, or repositories;
- extend the existing production capability context tests; do not replace or weaken them.

There is currently no Spring bean wiring for `IdentityService`; integration tests construct it directly. W-2 must introduce an application configuration that assembles the service from typed capabilities and a `ChallengeDeliveryPort` without synthesizing missing dependencies. The fixture receipt adapter satisfies delivery only in the fully open fixture graph. Later production delivery wiring replaces it in its own profile/configuration.

## TDD sequence and exact evidence matrix

Every RED is a behavioral assertion that fails for the intended missing behavior, not a compile failure. Record commands and assertion reasons in `work-item-02-red-green.md`.

### 1. Gate and graph RED

Create an `ApplicationContextRunner` matrix before fixture beans exist:

- no profile + opt-in absent/false: no fixture runner, receipt, or fixture delivery adapter;
- `development` and `test` + opt-in false: no fixture graph;
- `development` and `test` + explicit true plus supplied healthy dependencies: exactly one fixture runner and receipt adapter;
- no profile, `staging`, `production`, or `production-like` + true: startup fails with `fixture_profile_forbidden`;
- `development,production-like` and `test,staging` + true: startup fails with the same safe code;
- allowed profile + true + each missing/unhealthy capability in turn: startup fails closed;
- production-like without opt-in and without external crypto/signing: the existing production capability failure remains unchanged;
- production-like with healthy external capabilities and fixture opt-in: startup still fails for the forbidden fixture, and contains no fixture beans.

Inspect bean definitions as well as types: there is no fallback `UserDetailsService`, `JwtEncoder`, generated signer/key, fixture controller, alternate security filter chain, or unsigned-token component.

### 2. Evidence domain and repository RED

Unit-test `CREATED|EXISTING|REJECTED|CONFLICT` results, inactive/unknown identity, missing email, wrong identifier owner/type, stale expected version, and safe exception mapping. Prove first creation increments identity/security versions once, an existing result changes neither, and audit construction contains only allowlisted opaque fields.

### 3. PostgreSQL 18 migration and persistence RED

Run against PostgreSQL 18, never H2, and fail rather than skip when the container runtime is unavailable:

1. migrate an empty database V1→V4 and a retained accepted V3 snapshot V3→V4; validate, preserve prior rows, and prove rerun is a no-op;
2. cover every ID, enum, state/version, timestamp, unique, and foreign-key constraint with positive and negative cases;
3. prove functions reject a factor/recovery binding unless the active identity owns a verified `EMAIL`;
4. prove database transaction time supplies evidence and audit timestamps; no caller timestamp is accepted;
5. sequential and concurrent ensure calls produce one factor/recovery row, one registration audit per kind, and exactly one security/version increment per first creation;
6. inject failure after evidence insertion, after identity-version change, and after audit append for each operation; every boundary leaves the complete effect or none;
7. prove runtime can select and execute only the allowed functions, cannot directly insert/update/delete/truncate, and unrelated/relay roles cannot read or mutate the tables;
8. prove update/delete rejection for runtime and normal migrator operation while enforcement is active;
9. recreate application services against the same database and observe the same evidence references and versions;
10. assert W-2 leaves `outbox_event` and `outbox_delivery` empty.

### 4. Fixture journey RED

With real PostgreSQL, real AES-256-GCM/HMAC-SHA-256 test capabilities, random purpose-separated test keys, and the one-shot receipt adapter:

- first run creates and verifies the reserved protected email through `IdentityService`, then creates both evidence facts;
- second invocation in the same context and a fresh context over the same database return the same logical identity and evidence references, with one identifier/factor/recovery and no additional challenge or audit effect;
- an identifier-promotion conflict re-resolves the canonical winner rather than bypassing verification;
- wrong, missing, reused, expired, superseded, and locked receipt/code paths fail through the normal verification result and create no evidence;
- receipt take is one-shot, bounded, removed after use, and unavailable with the gate closed;
- injected failures do not trigger direct cleanup or seed rows; a completed retry converges only through normal ports where the existing WU4 state allows it.

### 5. Privacy and security RED

Use unique canaries for the reserved email, challenge code, credential-like value, private-key-like value, access token, and refresh token. Scan:

- application and captured logging events;
- startup failures, domain exceptions, serialized results, and object `toString()` values;
- audit, outbox, delivery, factor, and recovery rows;
- PostgreSQL logs and sanitized SQL error surfaces;
- HTTP responses and actuator output if enabled;
- XML/HTML/test reports and generated contract/build artifacts.

The reserved email may appear only encrypted in the existing challenge/identifier protected columns. Challenge plaintext and private key material appear nowhere persistent. Factor/recovery rows contain only opaque IDs, closed enums, versions, and timestamps. Do not print a canary in a failing assertion.

### 6. GREEN and refactor gates

Suggested narrow commands, adjusted only for actual class names:

```text
./gradlew test --tests '*DeterministicIdentityFixtureConfigurationTest' --tests '*IdentityEvidenceServiceTest'
./gradlew integrationTest --tests '*IdentityEvidencePersistenceIntegrationTest' --tests '*DeterministicIdentityFixtureIntegrationTest'
```

Then run:

```text
./gradlew clean test integrationTest check contractBundle --warning-mode all
```

Maintain at least 80% aggregate line and branch coverage and exercise every new typed outcome/branch. Rebuild the contract bundle and confirm its SHA-256 is byte-for-byte unchanged because W-2 adds no published contract. Run the existing secret, dependency, static, SBOM, architecture, migration, and production-startup gates. Inspect the scoped diff and obtain correctness/database and security reviews with no unresolved critical/high finding.

## Exclusions and dependencies

W-2 deliberately excludes:

- App Subject allocation, activation evaluation/state, onboarding outbox, relay, and UMS;
- OAuth authorization requests/codes, login UI, DPoP, access/refresh tokens, JWKS, and metadata;
- a development identity endpoint, admin endpoint, password, default user, basic authentication, or direct-login shortcut;
- production email/SMS provider selection, OTP UX, resend/rate-limit policy beyond the existing challenge bounds, and production delivery receipts;
- factor/recovery execution, replacement, disablement, revocation, independence policy, passkeys, TOTP, passwords, and recovery codes;
- deterministic internal IDs, codes, nonces, keys, signatures, or timestamps;
- secret-manager/cloud/HSM selection and production operational key custody;
- crash-atomic or multi-instance fixture provisioning;
- changes to IAM's published contracts or to Dutch/UMS repositories.

W-3 and later work may depend on the resolved opaque identity and persisted factor/recovery evidence. W-8 owns strict activation and is the first unit allowed to interpret these facts as prerequisites. W-7/W-13 own actual signed-token and authorization use of the injected signer. There is no human product decision or cloud/provider choice blocking W-2.
