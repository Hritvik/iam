Type: grilling
Status: resolved
Assignee: Codex
Parent: [Specify the shared first-party Identity Platform](../map.md)
Blocked by: 12, 13, 14

# Define the implementation handoff and build sequence

## Question

What vertical slices, dependency order, contract-first boundaries, migration strategy, acceptance journeys, ownership, release gates, and explicit deferrals turn the completed requirements and design into a build-ready TDD implementation plan?

## Decision

### Canonical ownership and repositories

- The shared Identity Platform is canonically owned and implemented in the dedicated `~/repositories/iam` repository. It is a portfolio security platform serving Dutch, Midas, Jarvis, and future first-party apps; Dutch does not own its runtime or release lifecycle.
- The IAM repository owns the Java/Spring modular application, IAM database migrations, OAuth/OIDC metadata and conformance configuration, platform OpenAPI, IAM-produced event schemas/fixtures, App Registration manifest schema/registry, deployable artifacts, runbooks, and infrastructure integration points.
- Dutch retains Dutch App Registration environment overlays/review requests, Dutch client integration, and the Dutch-owned UMS profile/mapping consumer. Midas, Jarvis, and later products own equivalent app integration and profiles rather than depending on Dutch UMS.
- Published contracts have one source of truth and are consumed by pinned version. Repositories must not maintain independently edited copies. Distribution may use a contract package/registry or an automated verified export chosen during repository setup.
- Existing `/services/iam` code under Dutch is prototype evidence. With no live identity population, implementation ports validated tests, behavior, and useful code deliberately; it does not preserve a misleading ownership boundary or treat prototype schema/API names as compatibility obligations.
- This Wayfinder remains the decision record until its resolved tickets and linked research are transferred or referenced from the IAM repository. Transfer must preserve provenance and links rather than silently copying fragments into contradictory documents.

### Contract-first foundation

Before production code, publish and validate:

1. App Registration/Product Security Policy manifest schema and example registrations for Dutch native and Dutch API/BFF/resource clients;
2. issuer/discovery and protected-resource metadata expectations;
3. platform error/correlation/idempotency conventions;
4. app-scoped onboarding, activation, security-version, departure, and deletion event schemas plus negative PII/secret schema tests;
5. app profile-readiness acknowledgement/snapshot OpenAPI;
6. access-token claim/profile contract and resource validation conformance fixtures;
7. database migration, outbox/inbox envelope, aggregate version, and compatibility conventions; and
8. development/test-only deterministic identity contract with explicit profile gating.

No generated Java class, Spring configuration, broker binding, or Dutch DTO is the contract source of truth.

### Vertical TDD build sequence

Each slice begins with failing behavioral/security tests and ends with an independently demonstrable journey and recorded evidence. Do not build all persistence layers first and postpone the cross-service journey.

#### Foundation — repository and security harness

- Create the Java LTS/Spring Boot modular application, dependency rules, supported PostgreSQL/Testcontainers environment, Flyway conventions, clock/ID/crypto ports, structured safe errors/correlation, outbox/inbox primitives, test key infrastructure, contract validation, coverage, secret/SBOM/dependency/static-analysis gates, and CI.
- Add module-boundary tests preventing protocol/web code from bypassing application/domain interfaces and preventing another service's database access.
- Exit: clean checkout validates contracts, starts against an empty migrated database, signs only with explicit non-production test keys, and proves production startup fails when required key/secret configuration is absent.

#### Slice A — Identity vault and verified bootstrap

- Implement Human Identity, typed Verified Identifier normalization, envelope encryption, keyed blind indexes, verification challenges, uniqueness/concurrency, security version, basic audit, and transactional identity lifecycle outbox.
- Add deterministic verified identities only under an isolated development/test profile; they traverse normal signed-token and persistence paths and cannot load in staging/production.
- Exit journey: a development client proves an email/phone challenge, creates exactly one Human Identity under retry/concurrency, and produces one PII-free committed lifecycle fact. Enumeration, expiry/reuse, log/event leakage, migration, and rollback tests pass.

#### Slice B — OAuth/OIDC client and token baseline

- Add manifest-reconciled App/Client/Resource Registrations, authorization code with exact redirects and S256 PKCE, OIDC state/nonce/issuer binding, app-specific subjects, single-resource RFC 9068 access tokens, opaque codes/refresh artifacts, JWKS/discovery, and local resource validation fixtures.
- Implement DPoP for Dutch native production profile from the start, with replay/nonce/key-loss behavior.
- Exit journey: the Dutch development native client completes external-browser authorization and receives a correctly bound token; wrong redirect/PKCE/issuer/audience/type/key/DPoP proofs fail. No global identity ID or PII appears.

#### Slice C — First app activation and Dutch profile onboarding

- Implement App Activation/prerequisite state, idempotent App Subject creation, app-scoped onboarding-ready event, durable relay adapter, and reconciliation snapshot.
- In Dutch UMS, implement transactional inbox + unique Member Profile/mapping + UMS outbox and `PROFILE_REQUIRED`, `PROFILE_PROVISIONING`, and `PROFILE_READY` HTTP behavior.
- Rename the production event to `iam.app-subject.onboarding-ready.v1`. If the existing `iam.identity.verified.v1` fixture/code must bridge development, define its `identityId` as the Dutch App Subject, dual-publish only for a bounded migration, and remove it before another product depends on the name.
- Exit journey: duplicate, concurrent, delayed, reordered, lost-ack, UMS-down, and reconciliation scenarios create exactly one Dutch Member Profile and one logical mapping event; Dutch is gated until ready while other apps remain unaffected. PII-negative contracts/log scans pass.

#### Slice D — Durable sessions, refresh families, and revocation

- Implement Platform SSO Sessions, app/device contexts, atomic rotating refresh families, replay response, bounded persistence, session listing, scoped/app/device/global logout, OIDC RP/back-channel logout, and app/global security-version projection.
- Exit journey: the same identity enters a second registered test app through SSO without sharing subjects; refresh concurrency/reuse, current-app logout, all-apps-on-device, global logout, stale security version, logout retry, and IAM-outage validation behave exactly as specified.

#### Slice E — Passkeys, assurance, step-up, and self-service recovery

- Implement WebAuthn Level 2 passkey enrollment/authentication, structured assurance, Product Security Policy step-up/recent-auth challenges, factor/identifier lifecycle, recovery codes, authenticated-device/another-passkey/verified-channel recovery, notifications, cooldowns, and restricted recovery session.
- Manual/operator recovery remains absent until two genuinely independent approvers exist.
- Exit journey: passkey-first use, synchronized passkey, lost device, recovery-code single use, verified-channel recovery, factor replacement, recent Strong enforcement, recovery global revocation, origin/RP/challenge attacks, and unavailable-evidence lockout pass.

#### Slice F — Registration governance and workload authority

- Implement manifest reconciliation/drift, environment promotion evidence, asymmetric client credentials, Workload Identity, own-behalf client credentials, credential rotation/emergency disablement, and the default-denied Delegation Workflow registry/exchange engine.
- Do not register a production delegation workflow without a concrete product use case and resource-owner acceptance tests.
- Exit journey: a workload reaches one permitted audience; human/workload confusion, scope/audience escalation, unregistered exchange, actor omission, recursive exchange, and compromised credential tests fail safely. A named staging-only one-hop workflow proves the mechanism.

#### Slice G — Privacy, administration, and lifecycle completion

- Implement app departure/reactivation, security locks, export, 30-day deletion/cancellation/finalization, product acknowledgements/reconciliation, protected audit access/integrity, bounded administrative commands, break-glass scaffolding, and retention jobs.
- Exit journey: app departure affects only Dutch; global deletion immediately removes authority, can be recovered inside 30 days, then destroys/pseudonymizes IAM data and drives app-owned anonymization without erasing lawful product evidence. No impersonation/manual recovery path exists.

#### Slice H — Cloud reconciliation and production hardening

- Import the separately produced cloud architecture into ticket 13's acceptance model; implement environment isolation, networking, managed database/broker/cache/key/object/telemetry adapters, infrastructure as code, budgets, alerts, backups, runbooks, and immutable promotion.
- Complete conformance, penetration/security/privacy review, load/capacity, signing/encryption/blind-index rotation, restore, failure-domain, outbox/DLQ/reconciliation, and incident exercises.
- Exit: every production gate in `Define verification and production acceptance` has linked evidence and no cloud-decision placeholder remains.

### Migration from the current Dutch prototype

- There is no production-account migration or compatibility burden. Never create a synthetic migration solely to preserve unused prototype records.
- Inventory the current Dutch IAM tests/code/contracts into `port`, `replace`, or `retire` against this specification. Port behavior only after its test is made contract-correct (especially App Subject rather than global Identity ID).
- Freeze new shared-IAM implementation under Dutch once the dedicated repository foundation exists. Dutch IAM prototype remains available temporarily as comparison until Slice C passes end to end, then is removed through a separate reviewed cleanup with no product code pointed at it.
- Dutch UMS migrations remain owned by Dutch. Evolve its mapping to the app-scoped subject using expand/backfill/dual-read-or-write only if persisted development data must be preserved; otherwise use a clean non-production migration before release.
- Preserve Git history through an intentional repository extraction/import method if valuable, but do not allow history mechanics to delay correcting the security boundary.

### Acceptance journeys across slices

The continuously running portfolio suite must prove:

- new identity → verified identifier → passkey → Dutch authorization → one Dutch profile → ready;
- existing identity → Midas/Jarvis test registration SSO → different App Subject/profile readiness, no Dutch profile disclosure;
- UMS delayed/down → Dutch profile-required/retry/reconciliation without duplicate profile;
- stolen/replayed code, refresh token, DPoP proof, ID token, wrong-audience token, workload token, and delegated token all fail in the correct component;
- refresh reuse, device logout, app logout, global logout, recovery, lock, and deletion have distinct verified blast radii;
- identifier/factor/recovery changes never leak PII or silently merge identities;
- app, IAM, database, broker, key, and notification outages produce documented honest behavior;
- backup restore, migration, key rotation, event replay, and consumer reconciliation converge without resurrecting deleted authority.

### Ownership during implementation

- **Identity Platform owner:** IAM domain/protocol/persistence, security libraries/conformance, contracts, manifests, keys, events, operations, incident response.
- **App owner:** app registration request, redirects/client integration, product profile/readiness, domain authorization, app-local session/logout, event consumer/reconciliation, retention/anonymization.
- **Resource owner:** audience/scopes, token validation, assurance challenges, security-version projection, workload/delegation acceptance.
- **Cloud solution owner:** provider/topology mapping and operational feasibility against ticket 13, then implementation support through production evidence.
- **Security reviewer:** threat/conformance/privacy/adversarial review; independent review is mandatory before production even if coding is agent-assisted.

For a sole developer, these are responsibility hats and review gates, not fictional simultaneous staff. Coding agents may implement and review, but cannot satisfy independent human approval for manual recovery or silently accept critical production risk.

### Release and compatibility gates

- Merge requires traceability, RED/GREEN evidence, targeted tests, contract compatibility, migration checks, ≥80% aggregate line/branch coverage plus critical-path completeness, formatting/static/security/dependency/secret scans, and reviewed diff.
- Staging promotion requires signed immutable artifact/SBOM provenance, environment manifest reconciliation, end-to-end client journeys, migration rehearsal, PII/log scan, key/config validation, and no unresolved critical/high defect.
- Production requires the complete evidence in `Define verification and production acceptance`, cloud reconciliation, independent security assessment, restore/rotation/failure/replay drills, documented accepted risks, incident contacts, cost/headroom, and forward-repair plan.
- Do not commit or push as part of the Wayfinder. Implementation work uses separately scoped plans/work items and reviewable changes.

### Explicit deferrals

- Third-party/public OAuth clients, customer tenants, dynamic untrusted client registration, social login, SAML enterprise federation, anonymous/guest identity, passwords, generic impersonation, automatic identity merge, runtime provider marketplace, shared cross-app profile synchronization, multi-region active-active issuance, self-managed Kubernetes/Kafka/PostgreSQL, and black-box risk scoring.
- Manual recovery remains deferred until true dual human approval exists.
- Production token exchange workflows remain unregistered until a named product workflow exists; the engine's presence grants no authority.
- WebAuthn Level 3-only capabilities, encrypted JWTs, opaque access-token/introspection profiles, and multi-resource access tokens require future evidence-backed decisions.

### Remaining external dependency

The requirements/design and application build sequence are implementation-ready. Infrastructure implementation is not ready until the separate cloud-solutions result is reconciled through the dedicated cloud ticket and satisfies ticket 13. No implementation agent should infer cloud choices from older Dutch ADRs while that dependency remains open.
