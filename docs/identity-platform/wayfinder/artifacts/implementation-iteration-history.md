# Implementation Planning Iteration History

## Scope

This history covers the implementation plan for the dedicated Identity Platform repository from Foundation through Slice C only. It records how specialist findings were reconciled before synthesis; it is not a substitute for the plan or the settled Wayfinder tickets.

## Round 1 — Specialist Review

Five independent reviews examined architecture, persistence and concurrency, security, test strategy, and implementation clarity for a sole developer working with coding agents.

### Converged findings

- Build one Java/Spring/PostgreSQL modular monolith with package-enforced boundaries and a single deployable artifact. Do not split IAM into premature microservices.
- Treat the dedicated IAM repository as a new runtime and Flyway lineage. The Dutch IAM prototype is behavioral evidence, not source to copy wholesale.
- Keep canonical, language-neutral IAM contracts in this repository and publish an immutable versioned bundle with a digest. Dutch pins the bundle; it does not maintain editable schema copies.
- Use opaque, stable App Subjects scoped to `(app registration, Human Identity)`. The global Human Identity identifier never leaves IAM.
- Commit authoritative state and the corresponding outbox row in one local transaction. Consumers assume at-least-once delivery and combine inbox deduplication with domain uniqueness.
- Keep IAM and UMS databases independent. No cross-service database reads, foreign keys, replicas, or shared migrations are permitted.
- Use PostgreSQL/Testcontainers for migration, locking, uniqueness, and rollback evidence. H2 is not release evidence.
- Make production configuration fail closed when signing, identifier encryption, or blind-index capabilities are missing. Development/test identities and keys remain explicitly isolated.
- Demonstrate behavioral RED, GREEN, and refactor evidence for every work item. Compilation or configuration failures do not count as behavioral RED.
- Do not claim production readiness from Foundation–Slice C. Cloud reconciliation, passkeys, recovery, full session/refresh behavior, SSO/logout, workload identity, and delegated access remain later work.

### Specialist disagreements requiring resolution

1. Whether App Subjects should be random persisted identifiers or cryptographically derived values.
2. Whether Slice B should issue refresh tokens before Slice D's family rotation and reuse response exists.
3. How Slice C can prove activation when passkey and recovery enrollment are later slices.
4. Whether the onboarding event should use an activation aggregate or a dedicated onboarding stream.
5. Whether the profile-state route itself should return `409` before readiness or provide a queryable state representation.
6. Whether UMS should synchronously acknowledge readiness to IAM.
7. Whether compatibility requires dual-publishing the prototype `iam.identity.verified.v1` event.

## Round 2 — Evidence Resolution

### R2-1 — App Subject generation

Use a cryptographically random, persisted, opaque App Subject with at least 128 bits of entropy. Enforce uniqueness both for `(app_registration_id, human_identity_id)` and for the public subject within an app. Persistence gives stability; randomness avoids key-rotation coupling and prevents structural correlation. "Derived" in earlier prose means established through the IAM mapping, not deterministically computed from the global identity.

### R2-2 — Refresh-token boundary

Do not advertise the refresh-token grant or issue refresh tokens through Slice C. Slice D owns the indivisible family, rotation, reuse-detection, and revocation behavior. Shipping a bearer refresh artifact without those controls would create a knowingly incomplete security boundary. Existing prototype tests remain evidence for the later slice.

### R2-3 — Activation prerequisites in the scoped journey

Do not weaken the settled rule that `ACTIVE` requires a verified identifier, a usable authentication factor, and a recovery path. The Foundation–Slice C automated journey uses isolated development/test fixtures that establish factor and recovery evidence through the same persistence and application ports. Ordinary production-like bootstrap without those prerequisites remains `PENDING_PREREQUISITES` and emits no onboarding-ready event. Passkey and recovery product flows remain Slice E.

### R2-4 — Onboarding event stream

Use an `APP_ONBOARDING` aggregate stream keyed by the activation identifier, with its own monotonic `onboardingVersion`; include `activationVersion` in the payload. This prevents UMS from inferring gaps from activation versions that were never intended for that consumer while retaining traceability to activation state.

### R2-5 — Profile HTTP semantics

Use two Dutch-owned surfaces:

- `GET /api/v1/me/profile-state` returns `200` with the local state (`PROFILE_REQUIRED`, optionally real `PROFILE_PROVISIONING`, or `PROFILE_READY`).
- `GET /api/v1/me` returns the standard `409 profile_required` error until a mapping is ready, then returns the profile.

Neither response echoes the App Subject or a global identity identifier. `PROFILE_PROVISIONING` is reported only when UMS has an actual accepted-but-incomplete asynchronous state; it is not manufactured for presentation.

### R2-6 — Reconciliation rather than transactional acknowledgement

UMS emits its PII-free member-mapping event through its local outbox and maintains a local checkpoint. IAM exposes only an app-scoped, privileged onboarding snapshot needed for repair. UMS does not make a synchronous IAM call inside its profile transaction, and delivery acknowledgement alone never establishes profile readiness.

### R2-7 — Compatibility policy

Publish only `iam.app-subject.onboarding-ready.v1`. There is no live consumer or released schema requiring dual publication of `iam.identity.verified.v1`. Contract-negative tests reject `identityId` and all identifier, credential, token, session, and cross-app fields.

### R2-8 — Contract ownership and distribution

IAM owns the canonical manifest, OAuth/token, IAM HTTP, envelope, and IAM-produced event schemas. Dutch owns UMS HTTP and Dutch-produced member-mapping schemas. The cross-repository boundary is an immutable ZIP plus checksum/digest; the remote registry is deliberately left to the cloud/tooling reconciliation without changing the format.

### R2-9 — Concrete cryptographic and identifier baseline

- Email normalization trims ASCII boundary whitespace, validates syntax, converts the domain with IDNA, and lowercases the domain only. It performs no provider-specific dot or plus rewriting.
- Phone normalization accepts explicit E.164 only and rejects ambiguous national numbers.
- Blind indexes use HMAC-SHA-256 with the domain-separated input `iam|<environment>|identifier|<type>|norm-v<version>|<canonical-value>`.
- Identifier ciphertext uses a versioned AES-256-GCM suite with explicit authenticated context and key version metadata.
- Production signing is exposed through a signing port and never falls back to embedded or ephemeral production keys. Cloud-specific custody remains a reconciliation gate.

## YAGNI Sweep

The implementation plan intentionally excludes the following from Foundation–Slice C:

- refresh-token issuance, families, rotation, reuse detection, or revocation;
- passkey enrollment, recovery product flows, portfolio SSO, global logout, and session fan-out;
- workload identity, token exchange, delegated service access, and impersonation;
- UserInfo, dynamic client registration, generic identity administration CRUD, and arbitrary custom claims;
- opaque access tokens, introspection, encrypted JWTs, multi-resource tokens, and cross-app visibility APIs;
- provider-specific cloud, broker, KMS, deployment, or secret-manager choices;
- generic broker SDK abstractions in the domain, full audit archival/chaining, and an IAM inbox before IAM consumes state-changing external events;
- dual publication of obsolete prototype events, invented historical contract versions, and compatibility machinery for nonexistent production data;
- implementations for Midas, Jarvis, Ledger, Gateway, mobile clients, or a generic profile service.

## Remaining external gate

Wayfinder ticket 16 remains open for reconciliation with the separately developed cloud solution. It can constrain production adapters and operations but does not block the cloud-neutral Foundation–Slice C implementation plan. Any conflict found there must update the affected settled ticket and this plan before production deployment.
