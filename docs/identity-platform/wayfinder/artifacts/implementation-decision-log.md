# Implementation Decision Log: Identity Platform Foundation through Dutch Onboarding

This file records the implementation decisions for the Foundation-through-Slice-C build. Behavioral commitments remain in the [Wayfinder](../map.md), the executable sequence is in the [implementation plan](../feature-implementation-plan.md), and specialist discussion is in the [iteration history](implementation-iteration-history.md).

## Trivial decisions

- D-12: Legacy scaffold retirement — remove the non-authoritative Go scaffold when the Java foundation build lands; retain its history only through version control. — Referenced in plan: Implementation Approach, Work Units and Sequencing.
- D-13: UMS profile HTTP split — use `GET /api/v1/me/profile-state` as a `200` state query and `GET /api/v1/me` as the gated profile resource returning `409 profile_required` until ready. — Referenced in plan: HTTP contracts, Work Units and Sequencing.
- D-14: Production-readiness claim — Foundation through Slice C is a development proving milestone, not a production release. — Referenced in plan: Outcome, Operational Readiness, Definition of Done.

## Full decisions

### D-1: One deployable with enforced internal modules

- **Question:** What runtime and source shape gives a sole developer clear security boundaries without creating distributed-system overhead?
- **Decision:** Build one Java 25/Spring Boot/PostgreSQL deployable under `src/main/java/dev/distracted/iam`, divided into `bootstrap`, `identity`, `registration`, `authorization`, `activation`, `messaging`, and `platform`. A module exposes application interfaces and immutable messages; another module may not access its persistence package. Architecture tests enforce those rules.
- **Rationale:** The settled platform choice is a modular monolith. Package enforcement supplies reviewable boundaries while preserving one transaction boundary and one operational unit.
- **Evidence:** Wayfinder issues [06](../issues/06-select-platform-and-technology-stack.md) and [15](../issues/15-define-implementation-handoff.md); Round 1 architecture and junior-developer reviews; [discovery notes](.discovery-notes.md).
- **Rejected alternatives:**
  - Multiple IAM services — rejected because no measured scaling or isolation need justifies extra stores and failure modes.
  - A Gradle multi-project build for each domain — rejected because package boundaries and tests meet the present need with less ceremony.
  - Porting the Go placeholder — rejected because it contradicts the settled Java/Spring platform decision.
- **Specialist owner:** Identity Platform architect.
- **Revisit criterion:** A measured independent scaling, release, or failure-isolation requirement cannot be satisfied within the deployable.
- **Dissent (if any):** None.
- **Driven by rounds:** [R1](implementation-iteration-history.md#round-1--specialist-review).
- **Dependent decisions:** D-2, D-3, D-4, D-9.
- **Referenced in plan:** Outcome, Runtime and module shape, Work Units and Sequencing.

### D-2: PostgreSQL is the persistence acceptance target

- **Question:** How are schema, uniqueness, locking, and transaction claims proved?
- **Decision:** IAM owns a new, forward-only Flyway lineage in `src/main/resources/db/migration`; persistence and migration tests run against the supported PostgreSQL major through Testcontainers. H2 is not an acceptance target. Dutch UMS keeps its own Flyway lineage and credentials.
- **Rationale:** The critical invariants depend on PostgreSQL constraints, locks, and transaction behavior and cannot be established with an in-memory substitute.
- **Evidence:** Wayfinder issues [11](../issues/11-design-persistence-cryptography-and-messaging.md), [14](../issues/14-define-verification-and-production-acceptance.md), and [15](../issues/15-define-implementation-handoff.md); Dutch prototype H2 use recorded in [discovery notes](.discovery-notes.md).
- **Rejected alternatives:**
  - Copy Dutch migration numbers — rejected because IAM is a new owner/runtime with no live production data.
  - H2 for fast persistence acceptance — rejected because its dialect and concurrency behavior do not prove PostgreSQL invariants.
  - Cross-service schema or database access — rejected by the service ownership boundary.
- **Specialist owner:** Database reviewer.
- **Revisit criterion:** None for the ownership boundary; the supported PostgreSQL major may change through a tested upgrade.
- **Dissent (if any):** None.
- **Driven by rounds:** [R1](implementation-iteration-history.md#round-1--specialist-review).
- **Dependent decisions:** D-4, D-8, D-9, D-10.
- **Referenced in plan:** Persistence and transaction model, Testing Strategy, Work Units and Sequencing.

### D-3: Canonical contracts are immutable IAM publications

- **Question:** How do IAM and independently owned applications share contracts without creating editable copies?
- **Decision:** IAM owns language-neutral contracts under `contracts/` with `contracts/catalog.yaml` as the index. A release produces `iam-contracts-<semver>.zip` and `iam-contracts-<semver>.sha256`; consumers pin both version and digest. Dutch owns its UMS HTTP and Dutch-produced event schemas but imports the IAM bundle as read-only test input. The remote registry remains unspecified.
- **Rationale:** This provides one source of truth now without prematurely selecting cloud artifact infrastructure.
- **Evidence:** Wayfinder issues [12](../issues/12-define-apis-events-and-app-integration.md) and [15](../issues/15-define-implementation-handoff.md); [R2-8](implementation-iteration-history.md#r2-8--contract-ownership-and-distribution).
- **Rejected alternatives:**
  - Independently maintained contract copies — rejected because they drift.
  - Generated Java DTOs as the canonical contract — rejected because consumers may use other languages.
  - Selecting a cloud registry now — rejected by the recorded scope boundary.
- **Specialist owner:** Identity Platform contract owner.
- **Revisit criterion:** Cloud reconciliation selects a registry; bundle contents, immutability, and digest pinning remain unchanged.
- **Dissent (if any):** None.
- **Driven by rounds:** [R1](implementation-iteration-history.md#round-1--specialist-review), [R2-8](implementation-iteration-history.md#r2-8--contract-ownership-and-distribution).
- **Dependent decisions:** D-5, D-6, D-7, D-11.
- **Referenced in plan:** Contract ownership and publication, Work Units and Sequencing, Definition of Done.

### D-4: Identifier protection has one concrete baseline

- **Question:** What normalization, lookup, and encryption rules must all implementations and tests share?
- **Decision:** Email normalization trims ASCII boundary whitespace, validates syntax, IDNA-normalizes and lowercases the domain only; it does not rewrite dots or plus tags. Phone accepts explicit E.164 only. The blind-index input grammar is `iam|<environment>|identifier|<type>|norm-v<version>|<canonical-value>` and is protected with HMAC-SHA-256. Canonical/display values use versioned AES-256-GCM authenticated encryption with row-bound AAD and key-version metadata.
- **Rationale:** Concrete algorithms and grammars prevent silent identity splitting, merging, and offline enumeration while leaving key custody behind ports.
- **Evidence:** Wayfinder issue [11](../issues/11-design-persistence-cryptography-and-messaging.md); [R2-9](implementation-iteration-history.md#r2-9--concrete-cryptographic-and-identifier-baseline).
- **Rejected alternatives:**
  - Lowercasing the full email or provider-specific rewrites — rejected because provider semantics differ and may merge distinct addresses.
  - Unkeyed identifier hashes — rejected because low-entropy identifiers are enumerable.
  - Database encryption alone — rejected because database readers would still see raw PII.
- **Specialist owner:** Security reviewer.
- **Revisit criterion:** A versioned normalization or crypto migration is approved with overlap/backfill evidence.
- **Dissent (if any):** None.
- **Driven by rounds:** [R1](implementation-iteration-history.md#round-1--specialist-review), [R2-9](implementation-iteration-history.md#r2-9--concrete-cryptographic-and-identifier-baseline).
- **Dependent decisions:** D-8, D-10.
- **Referenced in plan:** Identifier and challenge contracts, Security Posture, Work Units and Sequencing.

### D-5: App Subjects are random persisted mappings

- **Question:** How is the public human subject made stable within one app and unlinkable across apps?
- **Decision:** Generate a CSPRNG-backed opaque value with at least 128 bits of entropy, encoded with the `aps_` prefix, and persist it once. Enforce uniqueness for `(app_registration_id, human_identity_id)` and `(app_registration_id, app_subject)`. Only `app_subject` crosses the app boundary.
- **Rationale:** Persistence provides stability while randomness avoids structural correlation and signing/encryption-key rotation coupling.
- **Evidence:** Wayfinder issues [01](../issues/01-define-identity-trust-and-privacy-boundaries.md), [07](../issues/07-design-tokens-claims-and-resource-validation.md), and [11](../issues/11-design-persistence-cryptography-and-messaging.md); [R2-1](implementation-iteration-history.md#r2-1--app-subject-generation).
- **Rejected alternatives:**
  - Expose Human Identity ID — rejected because it enables cross-app correlation.
  - Deterministic cryptographic derivation — rejected because stability becomes coupled to key/algorithm rotation.
  - Generate on every token request — rejected because the subject would not be stable.
- **Specialist owner:** Security reviewer.
- **Revisit criterion:** None without a new privacy-boundary decision and migration design.
- **Dissent (if any):** The persistence specialist suggested derived-and-persisted; the team committed to random-and-persisted because it has fewer rotation risks.
- **Driven by rounds:** [R1](implementation-iteration-history.md#round-1--specialist-review), [R2-1](implementation-iteration-history.md#r2-1--app-subject-generation).
- **Dependent decisions:** D-6, D-7, D-9, D-11.
- **Referenced in plan:** App Subject and activation model, OAuth/token contract, Event contracts, Work Units and Sequencing.

### D-6: Slice B excludes refresh issuance

- **Question:** Should the first authorization-code slice issue refresh tokens before refresh-family security exists?
- **Decision:** Through Slice C, authorization metadata does not advertise the refresh grant and the token endpoint does not issue refresh tokens. Slice D introduces family persistence, atomic rotation, reuse detection, and revocation as one security unit.
- **Rationale:** A bearer refresh credential without its replay response and revocation model is a knowingly incomplete boundary.
- **Evidence:** Slice D ownership in Wayfinder issue [15](../issues/15-define-implementation-handoff.md); [R2-2](implementation-iteration-history.md#r2-2--refresh-token-boundary).
- **Rejected alternatives:**
  - Issue non-rotating refresh tokens temporarily — rejected as unsafe and likely to become permanent.
  - Build Slice D family behavior inside this plan — rejected by scope.
- **Specialist owner:** OAuth/security reviewer.
- **Revisit criterion:** Slice D is explicitly started with its full acceptance suite.
- **Dissent (if any):** The persistence specialist proposed creating family state in Slice B; security, architecture, and test reviews rejected partial issuance.
- **Driven by rounds:** [R1](implementation-iteration-history.md#round-1--specialist-review), [R2-2](implementation-iteration-history.md#r2-2--refresh-token-boundary).
- **Dependent decisions:** D-7.
- **Referenced in plan:** OAuth/token contract, Security Posture, Cut for Scope.

### D-7: Access tokens use a closed claim profile and native DPoP

- **Question:** What exact token surface is implemented for Dutch native authorization?
- **Decision:** Human access tokens are signed RFC 9068 JWTs with JOSE `typ=at+jwt`, an allowlisted asymmetric `alg`, and `kid`. Required claims are `iss`, `sub` (App Subject), scalar `aud`, `exp`, `iat`, `jti`, `client_id`, `token_profile=human_access`, `token_version=1`, `subject_kind=app_subject`, space-delimited `scope`, `app_id`, and `security_version`; add `acr`, `amr`, and `auth_time` only when required by policy. Native production tokens require `cnf.jkt` and a validated DPoP proof. No arbitrary claim bag is allowed.
- **Rationale:** A closed profile prevents type, audience, and privacy drift between issuer and resources.
- **Evidence:** Wayfinder issues [05](../issues/05-design-app-registration-and-security-policy.md), [07](../issues/07-design-tokens-claims-and-resource-validation.md), [12](../issues/12-define-apis-events-and-app-integration.md), and [14](../issues/14-define-verification-and-production-acceptance.md).
- **Rejected alternatives:**
  - Bearer tokens for the native production profile — rejected because the settled profile is sender-constrained.
  - Multi-audience or portfolio tokens — rejected because audience isolation is the default.
  - Email, phone, roles, or profile claims — rejected by privacy and product-authorization ownership.
- **Specialist owner:** OAuth/security reviewer.
- **Revisit criterion:** A new versioned token profile is approved and consumers have migration evidence.
- **Dissent (if any):** None.
- **Driven by rounds:** [R1](implementation-iteration-history.md#round-1--specialist-review).
- **Dependent decisions:** D-11.
- **Referenced in plan:** OAuth/token contract, Testing Strategy, Security Posture.

### D-8: Development identities are isolated fixtures, not alternate authentication

- **Question:** How can the build provide deterministic test identities without creating a production bypass?
- **Decision:** Put deterministic identity bootstrap behind development/test-only wiring, an explicit opt-in, `.invalid` identifiers, and startup rejection in staging/production. It must use normal application ports, PostgreSQL persistence, identifier protection, subject allocation, and configured non-production signing; production-like startup with missing external crypto/signing capability fails closed.
- **Rationale:** Determinism makes tests reproducible, but bypassing normal writes or token signing would test a different system and create an accidental backdoor.
- **Evidence:** Wayfinder issues [14](../issues/14-define-verification-and-production-acceptance.md) and [15](../issues/15-define-implementation-handoff.md); Round 1 security review.
- **Rejected alternatives:**
  - Always-present `/dev` endpoint guarded only by a profile string — rejected as insufficient defense in depth.
  - Hardcoded signing/encryption keys — rejected by the secret boundary.
  - Unsigned or ad-hoc tokens — rejected because they do not exercise the protocol path.
- **Specialist owner:** Security reviewer.
- **Revisit criterion:** The fixture is no longer needed by local/portfolio acceptance tests.
- **Dissent (if any):** None.
- **Driven by rounds:** [R1](implementation-iteration-history.md#round-1--specialist-review), [R2-3](implementation-iteration-history.md#r2-3--activation-prerequisites-in-the-scoped-journey).
- **Dependent decisions:** D-10, D-11.
- **Referenced in plan:** Development/test fixture contract, Security Posture, Work Units and Sequencing.

### D-9: Transactional messaging uses an immutable fact and mutable delivery record

- **Question:** How are state changes delivered durably without claiming broker exactly-once semantics?
- **Decision:** The source transaction writes immutable `outbox_event` data; relay progress lives in `outbox_delivery`. The relay claims bounded work with PostgreSQL row locking/leases, publishes outside the source transaction, and acknowledges afterward. Consumers use an inbox key `(producer,event_id)`, a payload fingerprint, aggregate-version rules, and a separate domain uniqueness constraint. Same ID with different content is quarantined.
- **Rationale:** This preserves the source fact, supports retries and poison handling, and makes publish-before-ack duplicates an explicit tested behavior.
- **Evidence:** Wayfinder issues [11](../issues/11-design-persistence-cryptography-and-messaging.md), [12](../issues/12-define-apis-events-and-app-integration.md), and [14](../issues/14-define-verification-and-production-acceptance.md); Round 1 persistence review.
- **Rejected alternatives:**
  - Mark published inside the source transaction — rejected because broker publication cannot be atomically committed with PostgreSQL.
  - Inbox deduplication alone — rejected because two distinct events could still create two profiles.
  - Broker exactly-once assumptions — rejected because transport portability is required.
- **Specialist owner:** Persistence/messaging reviewer.
- **Revisit criterion:** A different transport adapter is introduced; transaction and idempotency semantics remain.
- **Dissent (if any):** None.
- **Driven by rounds:** [R1](implementation-iteration-history.md#round-1--specialist-review).
- **Dependent decisions:** D-10, D-11.
- **Referenced in plan:** Persistence and transaction model, Event contracts, On-Call Resilience Posture, Work Units and Sequencing.

### D-10: Activation remains strict in the proving journey

- **Question:** How can Slice C demonstrate an active app before passkey and recovery product flows exist?
- **Decision:** `ACTIVE` still requires a verified identifier, usable factor, recovery path, and app prerequisites. The development/test fixture establishes factor and recovery evidence through normal application and persistence ports. All ordinary bootstrap identities without that evidence remain `PENDING_PREREQUISITES` and emit no onboarding-ready event.
- **Rationale:** A demo must not weaken a production invariant. The fixture supplies controlled evidence; it does not redefine activation.
- **Evidence:** Wayfinder issues [01](../issues/01-define-identity-trust-and-privacy-boundaries.md), [05](../issues/05-design-app-registration-and-security-policy.md), and [15](../issues/15-define-implementation-handoff.md); [R2-3](implementation-iteration-history.md#r2-3--activation-prerequisites-in-the-scoped-journey).
- **Rejected alternatives:**
  - Treat verified identifier as sufficient for `ACTIVE` — rejected because it removes factor and recovery safeguards.
  - Pull full passkey/recovery UX into Slice C — rejected by scope and slice order.
- **Specialist owner:** Identity domain/security reviewer.
- **Revisit criterion:** Never by implementation convenience; only a new settled assurance decision can change the invariant.
- **Dissent (if any):** None.
- **Driven by rounds:** [R1](implementation-iteration-history.md#round-1--specialist-review), [R2-3](implementation-iteration-history.md#r2-3--activation-prerequisites-in-the-scoped-journey).
- **Dependent decisions:** D-11.
- **Referenced in plan:** App Subject and activation model, Development/test fixture contract, Work Units and Sequencing.

### D-11: One app-scoped onboarding event and snapshot repair path

- **Question:** What event and reconciliation contract creates one Dutch Member Profile without exposing a global identity?
- **Decision:** Publish only `iam.app-subject.onboarding-ready.v1` on aggregate type `APP_ONBOARDING`, keyed by activation ID and ordered by `onboardingVersion`. Its envelope has `eventId`, `eventType`, `schemaVersion`, `occurredAt`, `producer`, `environment`, `aggregate{type,id,version}`, `correlationId`, `causationId`, `destination{appRegistrationId}`, and `payload`. Payload has `appRegistrationId`, `appSubject`, `activationId`, `activationState`, `activationVersion`, `onboardingReason`, `onboardingVersion`, and `requiredProfileState`. UMS emits `dutch.member-profile.mapping-changed.v1` with `appRegistrationId`, `appSubject`, `memberId`, `mappingVersion`, `profileState`, and `lifecycleState` in the same envelope. Repair uses an authenticated app-scoped IAM snapshot; UMS never calls IAM synchronously inside its profile transaction.
- **Rationale:** A dedicated onboarding stream prevents consumers inferring missing activation events; an app-scoped snapshot repairs lost delivery without database coupling.
- **Evidence:** Wayfinder issues [11](../issues/11-design-persistence-cryptography-and-messaging.md), [12](../issues/12-define-apis-events-and-app-integration.md), and [15](../issues/15-define-implementation-handoff.md); [R2-4](implementation-iteration-history.md#r2-4--onboarding-event-stream), [R2-6](implementation-iteration-history.md#r2-6--reconciliation-rather-than-transactional-acknowledgement), and [R2-7](implementation-iteration-history.md#r2-7--compatibility-policy).
- **Rejected alternatives:**
  - `iam.identity.verified.v1` or dual publication — rejected because there is no live compatibility burden and the name invites global-ID leakage.
  - Activation aggregate version as the consumer sequence — rejected because UMS does not consume every activation fact.
  - Synchronous readiness acknowledgement in the UMS transaction — rejected because it couples availability and cannot make a cross-service transaction atomic.
- **Specialist owner:** IAM and Dutch UMS integration owners.
- **Revisit criterion:** A new schema version is required by a semantic or incompatible field change.
- **Dissent (if any):** The test review proposed a readiness PUT; reconciliation evidence showed the event plus snapshot is sufficient for this slice.
- **Driven by rounds:** [R1](implementation-iteration-history.md#round-1--specialist-review), [R2-4](implementation-iteration-history.md#r2-4--onboarding-event-stream), [R2-6](implementation-iteration-history.md#r2-6--reconciliation-rather-than-transactional-acknowledgement), [R2-7](implementation-iteration-history.md#r2-7--compatibility-policy).
- **Dependent decisions:** D-13.
- **Referenced in plan:** Event contracts, HTTP contracts, Work Units and Sequencing, Testing Strategy.
