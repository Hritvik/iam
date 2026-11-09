# Feature Implementation Plan: Identity Platform Foundation through Dutch Onboarding

Build the dedicated IAM repository into a Java/Spring/PostgreSQL Identity Platform and prove its first app-scoped vertical slice with Dutch UMS. The implementation proceeds contract-first and outside-in through observed RED/GREEN/refactor cycles; Foundation, Slice A, Slice B, and Slice C form one development milestone, not a production release. The critical boundary is that only an opaque Dutch App Subject crosses from IAM to UMS—never a global identity ID, raw identifier, credential, authorization artifact, or token. ([D-14](artifacts/implementation-decision-log.md#d-14-production-readiness-claim))

## Outcome

The IAM repository contains one reproducible Spring Boot application with enforceable domain boundaries, its own PostgreSQL/Flyway lineage, language-neutral published contracts, protected verified identifiers, exact-redirect/S256 authorization code and DPoP-bound access-token behavior, durable App Subject/Activation state, and a transactional onboarding outbox.

The proving journey starts from an isolated deterministic development/test identity, authorizes Dutch, delays UMS if requested, and converges on exactly one Dutch Member Profile. Profile-required/readiness behavior, duplicate and lost-ack delivery, reconciliation, migration, and privacy-negative evidence are executable.

## User Stories

- **US-1:** As a person using a first-party app, I want one shared identity to authorize Dutch without exposing my identifier or correlating me in another app, so that portfolio sign-in is private by default.
- **US-2:** As Dutch UMS, I want an app-scoped, replay-safe onboarding fact, so that I create exactly one Member Profile without reading IAM data.
- **US-3:** As a Dutch client, I want an honest profile-required state until UMS is ready, so that delayed provisioning is safe and understandable.
- **US-4:** As the platform operator, I want deterministic local journeys and fail-closed production-like configuration, so that agent-assisted development cannot introduce a test authentication backdoor.
- **US-5:** As a future first-party app owner, I want versioned language-neutral contracts and app-isolated subjects, so that I can integrate without adopting Dutch's runtime or profile model.

## Constraints and Boundaries

- **Driving constraint:** Establish the canonical IAM implementation and first cross-service proving slice before more product integrations build against the Dutch prototype.
- **Recorded boundary:** Foundation through Slice C only, replacing the legacy scaffold and deliberately porting useful prototype behavior; cloud decisions and later slices are excluded. See [scope boundary](artifacts/scope-boundary.md).
- **Repository ownership:** IAM production code, migrations, and IAM contracts live in `~/repositories/iam`. Dutch-owned UMS work remains in `~/repositories/dutch/services/ums` and Dutch-owned contracts remain in `~/repositories/dutch/contracts`; this plan names those changes but does not move their ownership.
- **No cross-service persistence:** IAM and UMS keep separate databases, roles, migrations, transactions, and backups. They integrate only through published contracts, events, and the privileged app-scoped snapshot.
- **No compatibility fiction:** There is no live account or consumer population. Correct App Subject semantics replace misleading prototype fields rather than receiving dual-read/dual-publish machinery.
- **No external mutation:** Execution does not commit, push, publish to a remote registry, or choose a cloud provider without a separately authorized step.

## Implementation Approach

### Runtime and module shape

Use one Gradle-built Spring Boot deployable on Java 25, with Spring Security Authorization Server, Spring JDBC, Flyway, PostgreSQL, JUnit, Testcontainers, and architecture-boundary tests. Pin the current mutually compatible Spring Boot and managed dependency set when Foundation begins and commit the Gradle wrapper; do not inherit the Dutch prototype's Spring Boot 3.4.5 simply because it exists. ([D-1](artifacts/implementation-decision-log.md#d-1-one-deployable-with-enforced-internal-modules))

The foundation targets are `settings.gradle.kts`, `build.gradle.kts`, `gradle/`, `gradlew`, `gradlew.bat`, `src/main/java/dev/distracted/iam`, `src/test/java/dev/distracted/iam`, `src/integrationTest/java/dev/distracted/iam`, and `src/main/resources`. The package responsibilities are:

- `bootstrap`: process entry point and environment wiring only;
- `identity`: Human Identity, Verified Identifier, challenge, factor/recovery evidence, and security version;
- `registration`: app/client/resource manifests and local runtime registry;
- `authorization`: authorization request/code, token profile, signing port, DPoP, discovery, and JWKS;
- `activation`: App Subject, App Activation, prerequisite evaluation, onboarding stream, and snapshot;
- `messaging`: outbox fact/delivery, relay ports, envelope validation, and reconciliation support;
- `platform`: clocks/IDs/crypto ports, transaction/correlation/error conventions, and safe observability.

Persistence adapters remain private to their owning package. Architecture tests under `src/test/java/dev/distracted/iam/architecture` prevent web/protocol adapters from bypassing application ports and prevent a module from reaching another module's persistence types. Remove the legacy Go files when this foundation passes; they are not retained as a second runtime. ([D-12](artifacts/implementation-decision-log.md#d-12-legacy-scaffold-retirement))

### Contract ownership and publication

Contracts are authored before dependent production code and validated independently of Java. IAM's canonical tree is `contracts/catalog.yaml`, `contracts/manifest/`, `contracts/oauth/`, `contracts/http/`, `contracts/events/`, and `contracts/fixtures/{valid,invalid}`. `contractTest` validates OpenAPI, JSON Schema/AsyncAPI, examples, compatibility rules, and forbidden-field fixtures. A local release task produces an immutable `iam-contracts-<semver>.zip` plus `iam-contracts-<semver>.sha256`; Dutch pins both and never edits the imported IAM artifacts. ([D-3](artifacts/implementation-decision-log.md#d-3-canonical-contracts-are-immutable-iam-publications))

The initial catalog includes:

- App Registration/Product Security Policy schema and Dutch development examples for a `NATIVE_PUBLIC` client and one resource audience;
- issuer, discovery, JWKS, protected-resource metadata, exact redirect, grant, and S256 expectations;
- human-access-token conformance fixtures;
- the standard success/error/correlation envelope;
- shared event-envelope schema and `iam.app-subject.onboarding-ready.v1` schema;
- `GET /internal/v1/apps/{appRegistrationId}/onboarding` snapshot OpenAPI, authenticated as a registered workload and paged/cursor-bounded by app;
- PII/secret-negative fixtures that reject global identity fields, raw email/phone, credentials, codes, access/refresh tokens, session secrets, device fingerprints, cross-app subjects, and free-form payload maps.

Dutch owns and validates `dutch.member-profile.mapping-changed.v1` plus `/api/v1/me` and `/api/v1/me/profile-state`, while importing the IAM event/envelope bundle as read-only consumer input.

### Persistence and transaction model

Create a new IAM Flyway lineage under `src/main/resources/db/migration`; do not copy Dutch migration numbering. Each accepted command commits aggregate state, version, allowlisted audit fact, and immutable outbox event in one short local transaction. PostgreSQL constraints and expected-version updates—not process locks—enforce single-winner behavior. ([D-2](artifacts/implementation-decision-log.md#d-2-postgresql-is-the-persistence-acceptance-target))

Foundation through Slice C introduces focused relational tables for `human_identity`, `verified_identifier`, `verification_challenge`, fixture-only factor/recovery evidence where required by the normal model, `app_registration`, `client_registration`, `resource_registration`, `app_subject`, `app_activation`, `authorization_request`, `authorization_code`, `dpop_replay`, `outbox_event`, `outbox_delivery`, and reconciliation checkpoints. Security invariants are columns/constraints; versioned policy documents may use validated JSONB but identity state is not a generic JSON document.

`outbox_event` is immutable. `outbox_delivery` owns lease, attempt, acknowledgement, and quarantine state. Relay claims a bounded batch with PostgreSQL row locking/lease semantics, commits the claim, publishes through a transport port outside the state transaction, then records acknowledgement. Publish-before-ack duplication is expected. ([D-9](artifacts/implementation-decision-log.md#d-9-transactional-messaging-uses-an-immutable-fact-and-mutable-delivery-record))

### Identifier and challenge contracts

Email normalization trims ASCII boundary whitespace, validates syntax, converts the domain through IDNA, and lowercases only the domain. Phone accepts explicit E.164 only. Blind indexes use HMAC-SHA-256 over `iam|<environment>|identifier|<type>|norm-v<version>|<canonical-value>`; stored canonical/display values use versioned AES-256-GCM with row-bound AAD and key-version metadata. ([D-4](artifacts/implementation-decision-log.md#d-4-identifier-protection-has-one-concrete-baseline))

Verification challenges store only protected digests and bounded metadata. Their state is exactly `ISSUED`, `SUPERSEDED`, `CONSUMED`, `EXPIRED`, or `LOCKED`; resend supersedes the prior live challenge, attempts are bounded, and consumption is a conditional single-winner update. Responses and timing classes remain non-enumerating.

### App Subject and activation model

An App Subject is a persisted opaque `aps_` value with at least 128 bits of CSPRNG entropy. The database enforces one mapping for `(app_registration_id,human_identity_id)` and uniqueness of `(app_registration_id,app_subject)`. Global Human Identity IDs are confined to IAM. ([D-5](artifacts/implementation-decision-log.md#d-5-app-subjects-are-random-persisted-mappings))

Activation states are `PENDING_PREREQUISITES`, `ACTIVE`, `SUSPENDED`, and `DEPARTED`. For this milestone, only `PENDING_PREREQUISITES → ACTIVE` is exercised. `ACTIVE` still requires verified identifier, usable factor, recovery path, and satisfied registered app prerequisites. An ordinary identity missing any evidence remains pending and produces no onboarding-ready event. ([D-10](artifacts/implementation-decision-log.md#d-10-activation-remains-strict-in-the-proving-journey))

### Development/test fixture contract

Deterministic identities use reserved `.invalid` email values and live only in development/test wiring with a second explicit opt-in. Staging/production startup rejects the fixture configuration. Fixture setup invokes normal application ports for protected identifier, factor/recovery evidence, activation, App Subject, outbox, and configured non-production signing; it never inserts bypass rows, returns unsigned tokens, or supplies fallback production keys. ([D-8](artifacts/implementation-decision-log.md#d-8-development-identities-are-isolated-fixtures-not-alternate-authentication))

### OAuth/token contract

Register Dutch's development native client with exact redirect `dutch://oauth/callback`, authorization-code grant only, external-browser behavior, S256 PKCE, one resource audience, and no client secret. Prefix/wildcard/case/encoding/userinfo/fragment/environment variants fail. Authorization codes are opaque, high entropy, short lived, single use, exact-redirect and PKCE bound, and stored as protected digests.

The access token is a signed RFC 9068 JWT. Its JOSE header requires `typ: at+jwt`, one allowlisted asymmetric `alg`, and `kid`. The closed payload is `iss`, `sub`, scalar `aud`, `exp`, `iat`, `jti`, `client_id`, `token_profile: human_access`, `token_version: 1`, `subject_kind: app_subject`, space-delimited `scope`, `app_id`, and `security_version`, with conditional `acr`, `amr`, `auth_time`, and native `cnf.jkt`. Raw identifiers, global IDs, credentials, product roles/profile fields, and arbitrary claims are forbidden. ([D-7](artifacts/implementation-decision-log.md#d-7-access-tokens-use-a-closed-claim-profile-and-native-dpop))

DPoP validation covers signature and embedded public JWK, thumbprint binding, exact method and normalized target URI, proof time, `jti` replay, server nonce, and `ath` where an access token is presented. The signing adapter is a port with explicit algorithm/key ID. Tests may use committed public fixtures plus non-production private test material; production-like profiles require an externally supplied signer and never generate an ephemeral key. Do not advertise or issue refresh tokens through Slice C. ([D-6](artifacts/implementation-decision-log.md#d-6-slice-b-excludes-refresh-issuance))

### Event contracts

All event JSON uses the shared envelope:

`eventId, eventType, schemaVersion, occurredAt, producer, environment, aggregate{type,id,version}, correlationId, causationId, destination{appRegistrationId}, payload`.

`iam.app-subject.onboarding-ready.v1` uses aggregate type `APP_ONBOARDING`, aggregate ID equal to the opaque activation ID, and aggregate version equal to `onboardingVersion`. Its payload is exactly `appRegistrationId, appSubject, activationId, activationState, activationVersion, onboardingReason, onboardingVersion, requiredProfileState`. Only `ACTIVE` produces it. There is no `iam.identity.verified.v1` production or bridge event. ([D-11](artifacts/implementation-decision-log.md#d-11-one-app-scoped-onboarding-event-and-snapshot-repair-path))

Dutch UMS consumes with inbox identity `(producer,eventId)` and stores a canonical payload fingerprint. Same identity/same payload is success without another effect; same identity/different payload is quarantined. In the same UMS transaction it writes the unique App Subject→Member mapping, Member Profile, inbox/checkpoint, and `dutch.member-profile.mapping-changed.v1` outbox event. Domain uniqueness protects `(app_registration_id,app_subject)` independently of the inbox.

The Dutch mapping payload is exactly `appRegistrationId, appSubject, memberId, mappingVersion, profileState, lifecycleState`; it uses the shared correlation/causation envelope and contains no raw identifier or IAM global ID. UMS reconciliation reads only its app's bounded IAM onboarding snapshot and never joins IAM persistence or synchronously calls IAM inside the profile transaction.

### HTTP contracts

Successful platform JSON is `{ "data": ... }`. Errors are `{ "error": { "code": "stable_machine_code", "message": "safe message", "details": [], "correlationId": "opaque-id" } }`; `details` is optional and allowlisted. `X-Correlation-Id` is accepted only when syntactically bounded, otherwise generated, and is returned as a response header and propagated to events. It is never an authorization or data identifier.

Dutch `GET /api/v1/me/profile-state` returns `200` and a data object containing only `state` (`PROFILE_REQUIRED`, real `PROFILE_PROVISIONING`, or `PROFILE_READY`) and safe retry guidance. Dutch `GET /api/v1/me` returns `409` with `error.code=profile_required` until ready, then `200` with the Dutch-owned Member Profile. Neither response exposes App Subject or any global identity value. `PROFILE_PROVISIONING` is emitted only if an actual accepted-but-incomplete workflow exists. ([D-13](artifacts/implementation-decision-log.md#d-13-ums-profile-http-split))

## Work Units and Sequencing

Every unit starts by recording a failing behavioral assertion and its intended reason in the work record. GREEN records the exact command and passing result; refactor records the unchanged result and coverage. A compile failure, missing bean, or test that was already green is not RED evidence.

Execute one unit at a time unless two agents have disjoint file ownership and all shared contracts are already GREEN. For each unit, use this loop:

1. Create or update only the files named by that unit's ownership boundary.
2. Add the smallest behavioral test that expresses the next missing outcome, run its narrow test command, and retain the failing assertion and reason as RED evidence.
3. Add the minimum production change that makes the narrow command pass, then run the unit's broader GREEN command.
4. Refactor without adding behavior; rerun the GREEN command and the applicable coverage gate.
5. Stop at the unit boundary with a passing scoped diff. Do not start a dependent unit while any test, migration, contract check, or critical/high review finding from the current unit is unresolved.

| # | Work Unit | Story | Delivers | Justification | Depends On | Verification |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Foundation build and gates | US-4, US-5 | Java/Gradle application, package-boundary checks, PostgreSQL test harness, Flyway baseline, safe correlation/errors, coverage/static/dependency/SBOM/secret gates, and fail-closed configuration. | Foundation is required by the approved handoff. ([D-1](artifacts/implementation-decision-log.md#d-1-one-deployable-with-enforced-internal-modules)) | — | RED architecture/startup tests; GREEN `./gradlew test integrationTest check`; production-like startup fails without signer/encryption/blind-index capabilities. |
| 2 | Canonical contract catalog and publication | US-2, US-3, US-5 | Concrete manifest, token, HTTP, envelope, onboarding, snapshot, fixtures, bundle, and digest before producers/consumers. | The handoff explicitly requires contract-first integration. ([D-3](artifacts/implementation-decision-log.md#d-3-canonical-contracts-are-immutable-iam-publications)) | 1 | RED invalid/PII fixtures and missing-field examples; GREEN `./gradlew contractTest contractBundle`; checksum reproducibility check. |
| 3 | IAM migration and transaction primitives | US-4 | New Flyway lineage, immutable outbox fact, delivery state, audit/correlation columns, repository interfaces, and rollback-on-failure evidence. | Slice state must be durable without sharing databases. ([D-2](artifacts/implementation-decision-log.md#d-2-postgresql-is-the-persistence-acceptance-target)) ([D-9](artifacts/implementation-decision-log.md#d-9-transactional-messaging-uses-an-immutable-fact-and-mutable-delivery-record)) | 1, 2 | Empty-schema and previous-test-snapshot migration; failure before/after state/outbox write; constraints and permissions verified in PostgreSQL. |
| 4 | Slice A protected identifier and challenge | US-1, US-4 | Human Identity, normalized encrypted email/phone, keyed blind index, challenge state machine, uniqueness, security version, and PII-free lifecycle fact. | Slice A is the first authoritative identity path. ([D-4](artifacts/implementation-decision-log.md#d-4-identifier-protection-has-one-concrete-baseline)) | 3 | Property/unit tests plus concurrent duplicate registration, expiry/reuse/supersede/lock, ciphertext/blind-index assertions, and canary PII log/event scans. |
| 5 | Slice A deterministic fixture | US-4 | Explicitly gated verified test identity with factor/recovery evidence through normal ports and `.invalid` data. | The approved development journey requires repeatability without a production bypass. ([D-8](artifacts/implementation-decision-log.md#d-8-development-identities-are-isolated-fixtures-not-alternate-authentication)) | 4 | RED staging/production fixture-load tests; GREEN dev opt-in journey; missing crypto/signing configuration prevents production-like startup. |
| 6 | Slice B registration and authorization code | US-1, US-5 | Manifest-backed Dutch app/client/resource registration, exact redirect, S256 request/code persistence, single consumption, discovery and authorization metadata. | Dutch must prove the standard public-client path before activation. | 2, 3, 5 | Parameterized negative redirect and PKCE cases, state/nonce/issuer mix-up tests, concurrent code redemption, no refresh grant in metadata. |
| 7 | Slice B App Subject, access token, and DPoP | US-1, US-5 | Stable app-isolated subject, closed RFC 9068 token profile, explicit signer port/JWKS, native proof binding and replay store. | Tokens must be app scoped and sender constrained before Dutch relies on them. ([D-5](artifacts/implementation-decision-log.md#d-5-app-subjects-are-random-persisted-mappings)) ([D-7](artifacts/implementation-decision-log.md#d-7-access-tokens-use-a-closed-claim-profile-and-native-dpop)) | 6 | Subject stability/isolation/concurrency; wrong issuer/audience/type/alg/key; DPoP signature/thumbprint/htm/htu/iat/jti/nonce/ath/replay; token PII-negative scan. |
| 8 | Slice C activation and IAM onboarding outbox | US-1, US-2 | Strict activation prerequisite state, idempotent App Subject resolution, one app-scoped onboarding stream, relay port, and privileged snapshot. | The approved first app activation must remain separate from profile readiness. ([D-10](artifacts/implementation-decision-log.md#d-10-activation-remains-strict-in-the-proving-journey)) ([D-11](artifacts/implementation-decision-log.md#d-11-one-app-scoped-onboarding-event-and-snapshot-repair-path)) | 4, 7 | Missing prerequisite remains pending/no event; retry/concurrency yields one subject and logical onboarding version; publish-before-ack duplicates; app-scoped snapshot authorization. |
| 9 | Dutch UMS forward migration and consumer | US-2 | UMS inbox/checkpoint, app-subject mapping uniqueness, one Member Profile, Dutch mapping outbox, and contract-pinned consumer. | The vertical slice is incomplete until the independent consumer commits its local effect. | 2, 8 | Dutch `integrationTest`: duplicate/concurrent/distinct-event, payload mismatch quarantine, rollback injection, reorder/gap, UMS restart; exactly one mapping/profile and one logical mapping version. |
| 10 | Dutch profile-required and ready HTTP | US-3 | Queryable state plus gated profile resource with standard envelopes and correlation. | Clients need honest behavior while UMS is delayed. ([D-13](artifacts/implementation-decision-log.md#d-13-ums-profile-http-split)) | 9 | Controller/security integration tests: required and delayed state, ready profile, auth errors, correlation echo/generation, no App Subject/global ID/PII in response or logs. |
| 11 | Relay, reconciliation, and portfolio journey | US-1, US-2, US-3, US-4 | In-memory/test transport adapter, lost-ack and UMS-down recovery, snapshot reconciliation, and outside-in Foundation–C journey. | At-least-once convergence is the acceptance condition, not one happy delivery. | 8, 9, 10 | `portfolioTest`: delay/down/retry/duplicate/reorder/lost ack/lost delivery/reconciliation; REQUIRED→READY; one profile; unrelated app registration unaffected. |
| 12 | Release-candidate evidence and reviews | US-4, US-5 | Recorded RED/GREEN/refactor evidence, ≥80% line and branch coverage, migration/contract/privacy reports, secret/dependency/SBOM/static scan, security and code review findings, and reviewed diff. | The quality rules require auditable tests and review before handoff. ([D-14](artifacts/implementation-decision-log.md#d-14-production-readiness-claim)) | 1–11 | `./gradlew clean check contractTest integrationTest portfolioTest jacocoTestCoverageVerification`; contract bundle digest; secret scan; clean scoped diff; no critical/high finding. |

Work units 9–11 are executed in the Dutch repository under a separate work item/change set because this plan's artifact lives with IAM but does not transfer UMS ownership. If agent work runs in parallel, assign exclusive file ownership and integrate contracts before code; never let agents edit the same migration or contract source concurrently.

### Executable unit cards

The table defines sequence and outcome. These cards define the file boundary, first meaningful RED, GREEN command, refactor check, and safe stopping point for the implementing developer or agent. Test class names below are intended names; keep an equivalent name if the repository's conventions require it.

#### Unit 1 — Foundation build and gates

- **Ownership:** IAM root Gradle/wrapper files; `src/main/java/dev/distracted/iam/{bootstrap,platform}`; `src/main/resources`; `src/test/java/dev/distracted/iam/architecture`; and test-source-set configuration. Do not add identity or authorization behavior.
- **RED:** Add test-fixture packages containing a deliberate foreign-persistence dependency and make the architecture rule scan those fixtures; separately add startup tests that select a production-like profile without signer, encryption, or blind-index capabilities. Observe the rule and fail-closed assertions fail for the intended reasons without introducing a production-source violation.
- **GREEN:** Establish the application, package rules, test suites, PostgreSQL container support, correlation/error primitives, and configuration validation; run `./gradlew test integrationTest check`.
- **Refactor and stop:** Remove the deliberate boundary violation, run coverage/static/dependency/secret gates, and stop only when a clean checkout can execute the wrapper and the production-like negative startup tests remain GREEN. Remove the Go runtime only at this stop point.

#### Unit 2 — Canonical contract catalog and publication

- **Ownership:** IAM `contracts/**` and only the Gradle tasks needed for `contractTest` and `contractBundle`. Dutch contract files remain untouched until Unit 9.
- **RED:** Add representative valid examples plus invalid fixtures containing `identityId`, raw identifiers, tokens, or an undeclared field. Observe missing schemas or acceptance of a forbidden fixture.
- **GREEN:** Implement the catalog and pinned schemas listed under Contract ownership and publication; run `./gradlew contractTest contractBundle` and verify the ZIP against its SHA-256 file.
- **Refactor and stop:** Rebuild the bundle twice from unchanged inputs and compare digests. Stop with every example schema-valid, every negative fixture rejected for the asserted reason, and no generated bundle treated as editable source.

#### Unit 3 — IAM migration and transaction primitives

- **Ownership:** IAM Flyway migrations; repository/transaction ports and PostgreSQL adapters in `platform` and `messaging`; integration tests for migration, constraints, permissions, and rollback. Do not add Slice A domain behavior.
- **RED:** Against PostgreSQL, assert that an injected failure between aggregate persistence and outbox persistence leaves neither visible, and that an outbox fact cannot be mutated. Observe the assertions fail before the schema/repositories exist.
- **GREEN:** Add the new migration lineage, parameterized repositories, immutable `outbox_event`, mutable `outbox_delivery`, expected-version writes, and role boundaries; run `./gradlew integrationTest`.
- **Refactor and stop:** Rehearse migration from empty and the retained prior test snapshot, rerun `./gradlew check integrationTest`, and stop with rollback, constraints, and cross-schema permission negatives passing.

#### Unit 4 — Slice A protected identifier and challenge

- **Ownership:** IAM `identity` domain/application/persistence code, its migrations, and identity tests. Shared crypto interfaces stay in `platform`; do not edit authorization or activation packages.
- **RED:** Start with parameterized normalization and challenge transition tests, then add PostgreSQL concurrency tests for duplicate registration and single-winner challenge consumption. Seed canary PII and observe that the absent implementation cannot satisfy ciphertext, blind-index, and no-leak assertions.
- **GREEN:** Implement the pinned normalization, AES-256-GCM protection, HMAC blind index, identity/identifier uniqueness, challenge states, and security version through parameterized repositories; run `./gradlew test integrationTest`.
- **Refactor and stop:** Rerun property, concurrency, expiry/reuse/supersede/lock, and privacy scans. Stop with no raw canonical identifier stored outside protected columns and no PII in lifecycle facts or captured logs.

#### Unit 5 — Slice A deterministic fixture

- **Ownership:** IAM development/test-only fixture wiring and fixture tests. Reuse Unit 4 application ports; do not add a production endpoint or direct database seeding.
- **RED:** Assert that the fixture is unavailable without both the development/test profile and explicit opt-in, and that staging/production startup rejects the opt-in. Observe those assertions fail before fixture wiring exists.
- **GREEN:** Add reserved `.invalid` fixture data and establish verified identifier, factor evidence, recovery evidence, and configured non-production signing through normal ports; run the narrow fixture tests, then `./gradlew test integrationTest`.
- **Refactor and stop:** Inspect the production runtime graph for fixture beans and fallback keys. Stop only when the opt-in journey is deterministic and production-like startup still fails without external crypto/signing capabilities.

#### Unit 6 — Slice B registration and authorization code

- **Ownership:** IAM `registration` plus authorization-request/code portions of `authorization`, their migrations, and protocol tests. Do not issue access or refresh tokens yet.
- **RED:** Add parameterized tests for every disallowed redirect variant, missing/plain/wrong S256 verifier, issuer/state/nonce mix-up, code replay, and concurrent redemption; confirm the exact accepted Dutch redirect is the sole positive case.
- **GREEN:** Implement manifest-backed registrations, metadata/discovery, persisted protected authorization requests/codes, and conditional single-use redemption; run `./gradlew test integrationTest contractTest`.
- **Refactor and stop:** Rerun the full parameter matrix and assert metadata contains authorization code plus S256 but no refresh grant. Stop with one concurrent redemption winner and no raw code in persistence or logs.

#### Unit 7 — Slice B App Subject, access token, and DPoP

- **Ownership:** IAM App Subject persistence/resolution in `activation`; token, signer/JWKS, and DPoP portions of `authorization`; related migrations and tests. Do not activate an app or emit onboarding yet.
- **RED:** Add subject stability/isolation/concurrency tests, token header/claim allowlist tests, and the full DPoP negative matrix for signature, thumbprint, method, URI, time, `jti`, nonce, `ath`, and replay. Observe rejection/claim assertions fail before implementation.
- **GREEN:** Implement random persisted App Subjects, the explicit signing port/JWKS, the closed RFC 9068 profile, `cnf.jkt`, and durable replay protection; run `./gradlew test integrationTest contractTest`.
- **Refactor and stop:** Scan serialized tokens and captured diagnostics for forbidden fields, rerun concurrency and replay tests, and stop with refresh still absent from metadata and responses.

#### Unit 8 — Slice C activation and IAM onboarding outbox

- **Ownership:** IAM `activation` and onboarding portions of `messaging`, their migrations, the app-scoped snapshot adapter, and IAM tests. Do not edit Dutch UMS.
- **RED:** Assert that missing prerequisite evidence remains `PENDING_PREREQUISITES` with no event; concurrent/retried activation yields one subject and one logical onboarding version; publish-before-ack is redelivered; another app cannot read the snapshot.
- **GREEN:** Implement strict activation, atomic onboarding outbox intent, delivery lease/ack behavior, and authenticated bounded snapshot; run `./gradlew test integrationTest contractTest`.
- **Refactor and stop:** Inject failures on each side of the state/outbox write and after publish/before acknowledgement. Stop with atomic rollback, expected duplication, stable onboarding ordering, and app isolation proven.

#### Unit 9 — Dutch UMS forward migration and consumer

- **Ownership:** Dutch `services/ums/**` and Dutch-owned mapping-event contract under `contracts/**`; import the pinned IAM bundle read-only. Do not edit Dutch IAM, Ledger, Gateway, or mobile code.
- **RED:** In Dutch, add consumer tests for duplicate and concurrent delivery, distinct events for the same subject, same ID/different payload, rollback injection, reorder/gap, and restart. Observe more than one effect or missing quarantine before the new migration/consumer exists.
- **GREEN:** Add the forward UMS migration, inbox/fingerprint/checkpoint, unique App Subject mapping, Member Profile creation, and Dutch mapping outbox in one transaction; run `./gradlew :services:ums:test :services:ums:integrationTest` from the Dutch root.
- **Refactor and stop:** Validate the imported IAM fixture and Dutch-produced event schema, rerun migration from empty and the retained UMS test snapshot, and stop with exactly one mapping/profile and one logical mapping version.

#### Unit 10 — Dutch profile-required and ready HTTP

- **Ownership:** Dutch UMS controllers/application queries/error mapping and their contracts/tests only. Do not expose or alter IAM identifiers.
- **RED:** Add authenticated controller tests showing `profile-state` returns `PROFILE_REQUIRED` while `/me` returns `409 profile_required`, and that both become the pinned ready responses after the Unit 9 consumer commits. Add invalid/missing correlation-header and privacy-negative cases.
- **GREEN:** Implement the two surfaces and standard envelopes/correlation handling; run `./gradlew :services:ums:test :services:ums:integrationTest` from the Dutch root.
- **Refactor and stop:** Scan response bodies and captured logs for App Subject, global ID, and seeded PII canaries. Stop with auth failures, required/delayed/ready states, and correlation echo/generation passing.

#### Unit 11 — Relay, reconciliation, and portfolio journey

- **Ownership:** Test-only transport/harness code in IAM and Dutch, plus UMS reconciliation code needed to consume the already-pinned IAM snapshot. Production contracts change only by returning to Unit 2 and repeating dependent units.
- **RED:** Add the five outside-in journeys and explicitly fail delivery by delaying UMS, dropping acknowledgement, duplicating/reordering events, and simulating a lost delivery repaired from the snapshot.
- **GREEN:** Wire the test transport and bounded checkpointed reconciliation. From the Dutch root run `./gradlew :services:ums:test :services:ums:integrationTest`; from the IAM root run `./gradlew portfolioTest`, with that task starting or addressing the pinned Dutch UMS test fixture through the harness.
- **Refactor and stop:** Rerun from clean databases and after process restart. Stop only when every fault converges from required to ready with one profile, while an unrelated app registration remains unreadable and unaffected.

#### Unit 12 — Release-candidate evidence and reviews

- **Ownership:** Test/report configuration and evidence records only; production changes are returned to the owning unit and repeated through its RED/GREEN/refactor loop. No commit, push, or remote publication.
- **RED:** Review the evidence matrix and record each missing command, coverage threshold, privacy scan, migration rehearsal, or review as a failing release criterion; do not create a synthetic code failure.
- **GREEN:** In IAM run `./gradlew clean check contractTest integrationTest portfolioTest jacocoTestCoverageVerification`. From the Dutch root run `./gradlew :services:ums:clean :services:ums:check :services:ums:integrationTest`. Rebuild and verify the contract digest, then run the configured static, dependency, SBOM, secret, privacy, and scoped-diff checks from Unit 1.
- **Refactor and stop:** Obtain Java/Spring, database, code-quality, and security reviews; route every finding to its owning unit and rerun this gate. Stop with at least 80% line and branch coverage, no unresolved critical/high finding, a passing scoped diff, and the result labelled only as a development proving milestone.

## Definition of Done

- [ ] A clean IAM checkout builds with the committed wrapper, migrates an empty PostgreSQL database, validates module boundaries, and has no Go runtime path.
- [ ] Contract bundle and SHA-256 digest are reproducible; Dutch consumes the pinned bundle without an editable IAM schema copy.
- [ ] Each work unit has observed behavioral RED, minimal GREEN, refactor, and coverage evidence.
- [ ] Aggregate line and branch coverage are each at least 80%; identity uniqueness, challenge/code consumption, App Subject uniqueness, activation, outbox/inbox, DPoP replay, and profile uniqueness branches have complete scenario evidence.
- [ ] Production-like startup fails when external signing, identifier encryption, or blind-index capability is missing; deterministic fixtures cannot load in staging/production.
- [ ] Exact redirect and S256 PKCE negative suites pass; the native token is DPoP bound; refresh is neither advertised nor issued. ([D-6](artifacts/implementation-decision-log.md#d-6-slice-b-excludes-refresh-issuance))
- [ ] Duplicate, concurrent, delayed, reordered, publish-before-ack, UMS-down, and snapshot-repair cases converge on one Dutch Member Profile and one logical mapping version.
- [ ] `GET /api/v1/me/profile-state` and `GET /api/v1/me` exhibit the pinned required/ready behavior with standard errors and correlation.
- [ ] Seeded email, phone, credential, code, access-token, private-key, global-ID, and cross-app canaries are absent from UMS persistence, events, DLQ/quarantine payloads, logs, traces, metrics, errors, and APIs.
- [ ] IAM and UMS database-role negative tests prove neither can read the other's schema.
- [ ] Targeted tests, migrations, contract validation, static/dependency/SBOM/secret scans, and scoped diff review pass with no unresolved critical/high security defect.
- [ ] Nothing under Cut for Scope or Deferred (YAGNI) was built unless the operator changed scope or a listed trigger fired and was recorded.
- [ ] The handoff explicitly says “development proving milestone”; no production-readiness claim is made before ticket 16 and later-slice gates are complete.

## Testing Strategy

- **Outside-in journeys:** Start with the five failing portfolio behaviors: deterministic verified bootstrap; exact-redirect/S256/DPoP authorization; delayed profile required→ready; duplicate/lost-ack exactly-one profile; lost-delivery snapshot repair.
- **Unit/property tests:** Normalization Unicode/boundaries, HMAC grammar, immutable state transitions, activation policy, token claim allowlist, DPoP URI/time rules, envelope allowlist, error mapping, and canonical fingerprints.
- **PostgreSQL integration:** Empty and prior test-snapshot migrations, constraints, expected versions, concurrent identity/App Subject/code/profile winners, transaction failure injection, row claiming/leases, permissions, and restart recovery. No H2 substitute.
- **Protocol/contract tests:** Parameterized redirect/PKCE cases, discovery/JWKS/metadata, token header/claims/audience/type, DPoP proof matrix, OpenAPI/JSON Schema/AsyncAPI/examples, and invalid secret/PII fixtures.
- **Cross-service tests:** Run producer fixtures against the UMS consumer and UMS-produced fixtures against its schema; inject duplicate, mismatch, delay, reorder, gap, poison, outage, and reconciliation.
- **Privacy/log tests:** Seed unique canaries and scan captured logs, structured errors, events, quarantine/DLQ, non-IAM database snapshots, and API bodies. Never print raw artifacts when a test fails.
- **Test doubles posture:** Fake clocks, ID generators, CSPRNG outputs, delivery ports, and signers only at explicit ports in unit tests. Use real Spring Security filters, authorization-server components, PostgreSQL, Flyway, crypto implementations, and HTTP serialization in integration/release evidence.
- **Task gates:** `test` is fast domain/unit evidence; `contractTest` is language-neutral contracts; `integrationTest` is PostgreSQL/Spring/protocol evidence; `portfolioTest` is the IAM↔UMS journey; `check` aggregates formatting, architecture, static analysis, coverage, and tests. Container-backed release tests fail rather than silently skip when Docker is unavailable.

## Security Posture

- **PII and correlation:** Decrypt identifiers only through narrow IAM capabilities; ordinary lookup uses blind indexes. No raw identifier, blind index, Human Identity ID, App Subject echo, credential, token, or code enters logs or app-facing errors.
- **Protocol attacks:** Reject redirect confusion, PKCE downgrade/plain/missing verifier, code replay, issuer/audience/type/algorithm confusion, and all DPoP signature/binding/time/replay failures. State and nonce are bound and validated.
- **Secret handling:** No hardcoded credentials or production keys. Production-like profiles require externally configured signer, encryption, and blind-index ports and fail startup if absent. Private test keys are visibly non-production and unavailable to production wiring.
- **Enumeration and abuse:** Identifier/challenge responses are non-enumerating with bounded input and attempt limits. Rate-limit integration is a port in this slice; provider/distributed implementation waits for cloud reconciliation.
- **Input and SQL safety:** Schema-validate manifests, events, IDs, correlation headers, and HTTP bodies at boundaries. Repositories use Spring JDBC parameter binding only; identifiers never form SQL text.
- **Review gate:** A security-review agent reviews contracts, migrations, crypto wiring, OAuth/DPoP, logs, and diffs after GREEN; critical/high findings block the milestone.

## Operational Readiness

This milestone supplies application-level signals and release artifacts but is not production-ready. Record counters/gauges for safe reason codes, challenge outcomes, authorization failures, DPoP replay, outbox backlog/oldest age/attempt/quarantine, inbox duplicate/mismatch/gap, reconciliation variance, and profile state; labels contain only bounded enums and opaque app IDs. ([D-14](artifacts/implementation-decision-log.md#d-14-production-readiness-claim))

The test transport and signer adapters are replaceable ports, not production defaults. Provider topology, KMS/HSM custody, broker/DLQ, distributed rate limiting, backup/restore, SLO/load targets, deployment, alerts, and incident runbooks remain blocked on cloud reconciliation and later production gates.

## On-Call Resilience Posture

- A failed IAM transaction exposes neither state nor an outbox fact; a successful state transition always has durable publish intent.
- Relay work is bounded and lease-based. A crash after publish but before acknowledgement causes a duplicate, which UMS treats as success without a second profile.
- Poison, incompatible-version, same-ID/different-payload, and sequence-gap messages are quarantined with opaque diagnostics; they are never silently discarded.
- UMS unavailability leaves IAM onboarding durable. Profile endpoints remain honestly required; retry and reconciliation converge later without blocking unrelated app activations.
- Snapshot reconciliation is app-scoped, bounded, authenticated, and checkpointed. It cannot enumerate other apps or expose identifiers.
- Migrations are forward-only. Before any non-development release, rehearse from empty and the last released schema and document forward repair; this milestone does not claim a destructive rollback.

## Risks and Assumptions

### Risks

| ID | Risk | Impact | Mitigation | Owner |
| --- | --- | --- | --- | --- |
| R1 | Spring Boot 4/current Authorization Server integration differs materially from the Dutch prototype. | Ported tests or configuration may encode obsolete behavior. | Pin a current compatible set in Foundation, use official APIs, and port behavior only after contract-correct RED. | IAM implementation owner |
| R2 | Agent parallelism causes migration/contract drift or hides non-TDD implementation. | Conflicts and false evidence undermine security review. | Exclusive ownership per work unit, contract-first merge order, retained RED/GREEN commands, and one final diff/security review. | Sole developer/operator |
| R3 | DPoP breadth makes Slice B larger than anticipated. | The milestone may be delayed or tempted to ship bearer native tokens. | Keep DPoP in the native acceptance gate; reduce parallel features, never weaken the profile. | OAuth/security owner |
| R4 | UMS prototype data exists and is unexpectedly valuable. | A clean forward migration could discard local-only development records. | Inventory before migration; if preservation is explicitly required, add a scoped expand/backfill plan rather than silent dual behavior. | Dutch UMS owner |
| R5 | Cloud design conflicts with signer, broker, database, or environment ports. | Production adapters may require plan revision. | Keep ports cloud-neutral; reconcile ticket 16 and update affected decisions before production work. | Cloud solution owner |

### Assumptions

| ID | Assumption | What Changes If Wrong | Status |
| --- | --- | --- | --- |
| A1 | There is no live IAM/UMS production population or released event consumer. | Add explicit compatibility, data migration, and rollout work before replacing schemas/events. | Verified — Wayfinder issue 15 and scope record |
| A2 | Java 25 and a compatible current Spring Boot/Security set are supported at Foundation execution. | Pin the newest supported Java LTS/framework combination and record the deviation; contracts do not change. | Runtime-only |
| A3 | Container-backed PostgreSQL is available in local/CI release evidence. | Provide an equivalent isolated PostgreSQL test environment; do not fall back to H2 or skip. | Runtime-only |
| A4 | The IAM target remains without Git history until repository initialization. | History/provenance commands and scaffold removal review become normal Git operations once initialized. | Verified — discovery notes |

## Cut for Scope

This is work the approved boundary excludes, not work deferred for lack of evidence. It returns only if the operator changes the recorded scope.

### Later Identity Platform slices

- **Why cut:** Slices D–H—refresh families/sessions/logout, passkeys/recovery, workload/delegation, lifecycle/privacy administration, and production hardening—are explicitly outside Foundation through Slice C.
- **Source:** [Scope boundary](artifacts/scope-boundary.md) and Wayfinder issue [15](issues/15-define-implementation-handoff.md).

### Other products and edge clients

- **Why cut:** Midas, Jarvis, Ledger, Gateway, mobile implementation, and non-Dutch product profiles were expressly excluded; this slice creates extensible contracts, not their integrations.
- **Source:** [Scope boundary](artifacts/scope-boundary.md).

### Cloud infrastructure and production release

- **Why cut:** Provider, region, managed database/broker/cache/key/secret services, deployment topology, backups, observability backend, costs, and production evidence await the external cloud solution.
- **Source:** Open Wayfinder issue [16](issues/16-reconcile-cloud-solution.md).

## Deferred (YAGNI)

This is implementation machinery no current evidence supports. Each item has a concrete reopening trigger.

### Additional IAM deployables or Gradle modules

- **Why deferred:** One deployable and package tests meet all current boundaries; extra services/modules add release and consistency cost.
- **Reopen when:** Measured scale, availability, team ownership, or release isolation cannot be met in the monolith.
- **Source:** R1 architecture review.

### IAM consumer inbox

- **Why deferred:** Foundation–C has no IAM-owned inbound state-changing event consumer.
- **Reopen when:** A settled slice introduces such a consumer.
- **Source:** R1 persistence/YAGNI review.

### Remote contract registry and generated client SDKs

- **Why deferred:** A deterministic ZIP plus digest closes the cross-repository contract now; provider/tool choice belongs to cloud/tooling reconciliation.
- **Reopen when:** More than one consumer needs automated distribution or cloud reconciliation selects the registry.
- **Source:** [R2-8](artifacts/implementation-iteration-history.md#r2-8--contract-ownership-and-distribution).

### Legacy-event compatibility and historical versions

- **Why deferred:** No live consumer needs `iam.identity.verified.v1`, dual publication, or invented v0 fixtures.
- **Reopen when:** Evidence identifies a released consumer or persisted contract that cannot migrate atomically.
- **Source:** [R2-7](artifacts/implementation-iteration-history.md#r2-7--compatibility-policy).

### Generic administration, UserInfo, arbitrary claims, and broker SDK

- **Why deferred:** None is required by the proving journey; generic surfaces expand attack and maintenance scope.
- **Reopen when:** A named product journey has approved purpose, contract, authorization, privacy, and acceptance tests.
- **Source:** YAGNI sweep in [iteration history](artifacts/implementation-iteration-history.md#yagni-sweep).

## Specialist Handoffs for Implementation

- **TDD guide** — engage at each work unit before production code; needs the unit's story, pinned contract, and intended behavioral RED.
- **Java/Spring reviewer** — engage after each GREEN for framework correctness and package-boundary quality; needs the scoped diff and passing commands.
- **Database reviewer** — engage for IAM/UMS Flyway, concurrency, permissions, and transaction-failure units; needs migrations plus PostgreSQL integration results.
- **Security reviewer** — engage after Slices A, B, and C and at the final gate; needs threat-relevant contracts, captured privacy scans, dependency/SBOM/secret results, and diff.
- **Build-error resolver** — engage only when a build/configuration failure blocks the intended behavioral test; it must not replace RED with compilation failure.

## Sources and Plan Records

- **Feature specification:** [Identity Platform Wayfinder](map.md), especially [implementation handoff](issues/15-define-implementation-handoff.md).
- **Boundary and discovery:** [scope boundary](artifacts/scope-boundary.md), [discovery notes](artifacts/.discovery-notes.md).
- **Key settled decisions:** [identity/privacy](issues/01-define-identity-trust-and-privacy-boundaries.md), [registration policy](issues/05-design-app-registration-and-security-policy.md), [technology](issues/06-select-platform-and-technology-stack.md), [tokens](issues/07-design-tokens-claims-and-resource-validation.md), [persistence/messaging](issues/11-design-persistence-cryptography-and-messaging.md), [APIs/events](issues/12-define-apis-events-and-app-integration.md), and [verification](issues/14-define-verification-and-production-acceptance.md).
- **External open dependency:** [cloud reconciliation](issues/16-reconcile-cloud-solution.md).
- **Decision rationale and rejected alternatives:** [implementation decision log](artifacts/implementation-decision-log.md).
- **Team composition and round-by-round history:** [implementation iteration history](artifacts/implementation-iteration-history.md).
- **Official runtime references checked during discovery:** [Spring Boot system requirements](https://docs.spring.io/spring-boot/system-requirements.html), [Spring Security Authorization Server](https://docs.spring.io/spring-security/reference/servlet/oauth2/authorization-server/getting-started.html), [Oracle Java support roadmap](https://www.oracle.com/java/technologies/java-se-support-roadmap.html), and [Testcontainers for Java](https://java.testcontainers.org/).

## Recommendation

Ship the plan as the authoritative Foundation-through-Slice-C build sequence. Begin implementation with Work Unit 1 under TDD, but do not represent the result as production-ready until later slices, cloud reconciliation, and the full production gates are complete.
