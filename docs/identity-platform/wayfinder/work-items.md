# Work Items — Identity Platform Foundation through Dutch Onboarding

These work items descend from the [Identity Platform Foundation through Dutch Onboarding implementation plan](feature-implementation-plan.md). Work items are numbered `W-N` for cross-reference only. `Depends on` lines refer to other work items in this file. Work Units 1–3 are an accepted baseline: the foundation, canonical IAM contract bundle, and durable transaction/outbox primitives already exist and are inputs to the work below.

## Shared reference artifacts

- [Agent onboarding and current resume point](agent-work/onboarding.md) — accepted history, active board, future sequence, execution commands, and handoff rules for coding agents.
- [Recorded scope boundary](artifacts/scope-boundary.md) — Foundation through Slice C, with Dutch as the proving product and cloud choices excluded.
- [IAM contract catalog](../../../contracts/catalog.yaml) and [contract usage notes](../../../contracts/README.md) — canonical language-neutral artifacts consumed across IAM and Dutch.
- [Semantic conformance requirements](../../../contracts/conformance/semantic-requirements.yaml) — mandatory checks that cannot be expressed by JSON Schema alone.
- [Shared event envelope](../../../contracts/events/event-envelope.schema.json) — the common integration-event wrapper.
- [Standard error envelope](../../../contracts/http/error-envelope.schema.json) — the closed, privacy-safe error shape.

## W-1 — Finish protected-identifier rotation and challenge correctness

**Summary.** The protected-identifier slice exists but is not yet accepted. Finish the remaining rotation paths and make the database clock authoritative. Complete the missing concurrency, rollback, restart, migration, duplicate, isolation, and privacy evidence. Later identity and authorization work can then rely on this slice safely.

**Type.** AFK.

**Status.** Complete and independently accepted. The clean gate passed with 71 unit, 37 PostgreSQL integration, and 8 contract tests; correctness/database and security reviews reported no critical, high, or medium findings.

**Work to be done.**
- Complete read-old/write-new blind-index behavior across challenge resend and identifier promotion.
  - A challenge issued under an old readable key remains usable after the active write version changes, while promoted identifiers receive every required current lookup index.
- Use PostgreSQL transaction time for persisted issue, resend, expiry, lock, and consumption decisions.
- Isolate database-backed tests and complete the sequential and concurrent email/phone duplicate matrix.
- Exercise rollback at every aggregate, challenge, identifier, blind-index, and audit boundary.
- Prove restart durability and rehearse empty and retained-schema migrations.
- Scan persistence, audit, outbox, exceptions, application logs, PostgreSQL logs, serialized results, and reports for privacy canaries.

**Justification.** This is the unfinished portion of Work Unit 4 and is required before deterministic fixtures or authorization can safely depend on verified identities.

**References.**
- **Work Unit 4** — [protected identifier and challenge](feature-implementation-plan.md#unit-4--slice-a-protected-identifier-and-challenge) defines the state, concurrency, migration, and privacy outcomes.
- **Identifier contract** — [identifier and challenge contracts](feature-implementation-plan.md#identifier-and-challenge-contracts) defines normalization, protection, and non-enumerating behavior.
- **D-4** — Identifier protection uses one versioned normalization, AES-GCM protection, and keyed blind-index baseline.
- **Migration** — [`V3__protected_identity_and_challenges.sql`](../../../src/main/resources/db/migration/V3__protected_identity_and_challenges.sql) is the persisted contract this item completes.

**Acceptance criteria.**
- [x] An old-key challenge can be resent after rotation; its replacement uses active write versions and the old row remains readable only through configured historical keys.
- [x] Consuming an old-key challenge promotes every required lookup index atomically, and lookup still succeeds after the old version is retired.
- [x] PostgreSQL integration tests derive persisted time decisions from `transaction_timestamp()` rather than caller-supplied time.
- [x] Concurrent resend, correct/wrong verification, expiry, max-attempt, and duplicate-promotion races produce one legal winner and no partial effects.
- [x] Failure injection at every promotion boundary leaves either the full committed result or no result.
- [x] Restart, clean migration, retained-snapshot migration, test isolation, and the full privacy-canary matrix pass.
- [x] The published IAM contract bundle remains byte-for-byte unchanged.

**Depends on.** None.

## W-2 — Add the explicitly gated deterministic identity

**Summary.** Development and test environments need a repeatable identity journey through normal application ports. The fixture creates protected identifier, verification, factor, and recovery evidence without bypass rows. It requires an allowed profile and explicit opt-in. Production-like configurations reject it entirely.

**Type.** AFK.

**Status.** Complete and independently accepted. The clean gate passed with 139 unit, 47 PostgreSQL integration, and 8 contract tests; correctness/database and security reviews reported no critical, high, or medium findings.

**Work to be done.**
- Add development/test-only fixture configuration guarded by profile and explicit opt-in.
- Establish reserved `.invalid` fixture data through normal identity, challenge, verification, factor, and recovery operations.
- Make repeated setup deterministic and idempotent.
- Inspect the production runtime graph for fixture beans, fallback signers, and fallback cryptographic keys.

**Justification.** Work Unit 5 requires deterministic local journeys without creating an alternate production authentication mechanism.

**References.**
- **Work Unit 5** — [deterministic fixture](feature-implementation-plan.md#unit-5--slice-a-deterministic-fixture) defines ownership and stopping conditions.
- **Fixture contract** — [development/test fixture contract](feature-implementation-plan.md#developmenttest-fixture-contract) defines `.invalid` data, normal-port use, and dual gating.
- **D-8** — Development identities are isolated fixtures rather than alternate authentication.

**Acceptance criteria.**
- [x] Fixture setup is unavailable unless both an allowed development/test profile and explicit opt-in are present.
- [x] Staging, production, and production-like startup reject fixture opt-in.
- [x] Repeated setup converges on the same logical identity evidence without duplicate identifiers or direct database seeding.
- [x] Activation-required factor and recovery evidence is created through normal model ports.
- [x] Fixture execution leaks no identifier, challenge, credential, or key material, and production-like startup still fails without external cryptographic and signing capabilities.

**Depends on.** W-1.

## W-3 — Load and expose the pinned Dutch registration

**Summary.** IAM needs a runtime registration derived from the published Dutch manifest. This slice loads the native client and resource audience, rejects unsafe input, and exposes only contracted metadata. It establishes trusted inputs for authorization without issuing codes or tokens.

**Type.** AFK.

**Status.** Complete and independently accepted. The clean gate passed with 190 unit, 174 PostgreSQL integration, and 8 contract tests; correctness/database and security reviews reported no critical, high, or medium findings after the evidence wording was aligned with its exact public-graph scope.

**Work to be done.**
- Persist and load app, client, resource, redirect, grant, and product-security registration data.
- Validate registration input against the pinned contract and its language-neutral semantic rules.
- Publish the contracted authorization-server and protected-resource metadata.
- Keep OIDC discovery, ID tokens, refresh grants, and dynamic client registration outside this slice.

**Justification.** Work Unit 6 requires manifest-backed registration and metadata before authorization requests can be validated.

**References.**
- **Work Unit 6** — [registration and authorization code](feature-implementation-plan.md#unit-6--slice-b-registration-and-authorization-code) defines the manifest-backed client.
- **Registration contract** — [Dutch development registration](../../../contracts/manifest/dutch-development.app-registration.json) is the canonical client and resource input.
- **Metadata contracts** — [authorization server](../../../contracts/oauth/authorization-server-metadata.schema.json) and [protected resource](../../../contracts/oauth/protected-resource-metadata.schema.json) schemas define published metadata.

**Acceptance criteria.**
- [x] IAM loads exactly the pinned Dutch native client, `dutch://oauth/callback`, resource audience, authorization-code grant, and S256 requirement.
- [x] Wildcard, prefix, malformed, insecure, undeclared, or semantically invalid registrations fail safely.
- [x] Metadata advertises authorization code and S256, but not refresh, OIDC discovery, or an ID-token profile.
- [x] A clean migration and restart preserve the registration.
- [x] Responses and diagnostics contain no client secret, identifier, token, or unrestricted policy document.

**Depends on.** W-2.

## W-4 — Complete the single-use authorization-code journey

**Summary.** Dutch authorization accepts only its exact redirect and a valid S256 challenge. IAM protects request and code state and binds every relevant protocol value. Exactly one redemption succeeds. Token issuance remains a later slice.

**Type.** AFK.

**Status.** Complete and independently accepted. The clean gate passed with 239 unit, 243 PostgreSQL integration, and 8 contract tests at 93.93% line and 80.54% branch coverage. Correctness/database and security reviews reported no critical, high, or medium findings after two RED→GREEN correction cycles.

**Work to be done.**
- Add protected, expiring authorization-request and authorization-code persistence.
- Validate exact redirect and mandatory S256 at request and redemption boundaries.
- Bind issuer, client, app, redirect, state, nonce, and verifier to the transaction.
- Use conditional state changes for replay and concurrent-redemption safety.
- Cover redirect, PKCE, mix-up, expiry, restart, replay, and privacy matrices.

**Justification.** This is the protocol-complete authorization-code portion of Work Unit 6 and supplies trusted input to later token issuance.

**References.**
- **Work Unit 6** — [registration and authorization code](feature-implementation-plan.md#unit-6--slice-b-registration-and-authorization-code) defines the negative matrix and single-use behavior.
- **OAuth contract** — [OAuth/token contract](feature-implementation-plan.md#oauthtoken-contract) defines redirect, S256, protected storage, entropy, and expiry.
- **Client schema** — [app registration schema](../../../contracts/manifest/app-registration.schema.json) defines redirect and grant posture.
- **Conformance** — [semantic requirements](../../../contracts/conformance/semantic-requirements.yaml) defines cross-document invariants.

**Acceptance criteria.**
- [x] Only the exact Dutch redirect succeeds; case, encoding, prefix, suffix, fragment, userinfo, wildcard, environment, and scheme variants fail.
- [x] Missing, plain, malformed, or incorrect PKCE values fail without revealing protected state.
- [x] Issuer, client, app, redirect, state, and nonce mix-ups are rejected.
- [x] Codes are high entropy, short lived, stored only as protected digests, and absent from logs and errors.
- [x] Sequential and concurrent redemption produce exactly one winner, including after restart.
- [x] This item issues neither access nor refresh tokens.

**Depends on.** W-3.

## W-5 — Resolve stable app-isolated subjects

**Summary.** Successful authorization needs a subject stable within Dutch but unlinkable across apps. IAM generates and persists opaque App Subjects through one concurrency-safe mapping. Global Human Identity identifiers remain internal. This item proves subject semantics without token issuance or activation.

**Type.** AFK.

**Status.** Complete and independently accepted. The clean gate passed with 247 unit, 267 PostgreSQL integration, and 8 contract tests at 93.92% line and 80.90% branch coverage. Correctness/database and security reviews reported no critical, high, or medium findings after the concurrency, privacy, and exact-ACL evidence corrections.

**Work to be done.**
- Generate opaque `aps_` subjects with the required entropy.
- Persist one mapping per app registration and Human Identity pair.
- Resolve creation races through database uniqueness and typed outcomes.
- Prove isolation between Dutch and another registered test app.
- Prevent protocols and diagnostics from exposing Human Identity IDs.

**Justification.** Work Unit 7 requires the app-scoped identity boundary before issuing a human access token.

**References.**
- **Work Unit 7** — [App Subject, access token, and DPoP](feature-implementation-plan.md#unit-7--slice-b-app-subject-access-token-and-dpop) defines stability, isolation, and concurrency.
- **Subject model** — [App Subject and activation model](feature-implementation-plan.md#app-subject-and-activation-model) defines entropy and uniqueness.
- **D-5** — App Subjects are random persisted mappings, never deterministic global identifiers.
- **Token claims** — [human access-token claims](../../../contracts/oauth/human-access-token-claims.schema.json) later consume the App Subject as `sub`.

**Acceptance criteria.**
- [x] Repeated Dutch resolution returns one stable App Subject.
- [x] Concurrent first resolution creates one mapping and returns the winning subject consistently.
- [x] A second app receives a different subject for the same Human Identity.
- [x] Subjects meet prefix and entropy requirements and cannot be derived from Human Identity IDs.
- [x] Global identity values are absent from responses, events, logs, and cross-service artifacts.

**Depends on.** W-4.

## W-6 — Issue the closed signed human access token

**Summary.** Code redemption must produce a signed token containing only the published app-scoped claims. Signing remains behind an explicit capability and publishes matching public keys. Production-like profiles require externally supplied signing material. Refresh remains outside this milestone.

**Type.** AFK.

**Status.** Complete and independently accepted. The clean gate passed with 278 unit, 270 PostgreSQL integration, and 8 contract tests at 94.17% line and 81.06% branch coverage. Correctness/database and security reviews reported no critical, high, or medium findings after issuer-authority, signer-snapshot, numeric-strictness, privacy, and full-context restart corrections.

**Work to be done.**
- Issue the contracted signed token after successful code redemption.
- Publish the matching public key through the contracted JWKS shape.
- Enforce the closed JOSE header and claim allowlists.
- Bind issuer, app, client, audience, subject, security version, scope, and time.
- Prove fail-closed signing configuration in production-like profiles.

**Justification.** Work Unit 7 requires a signed RFC 9068 token before Dutch can authenticate with its App Subject.

**References.**
- **OAuth contract** — [OAuth/token contract](feature-implementation-plan.md#oauthtoken-contract) defines the closed header and claims.
- **D-6** — Slice B excludes refresh issuance and refresh-token families.
- **D-7** — Native access tokens use the closed app-scoped profile and DPoP binding.
- **Wire schemas** — [JOSE header](../../../contracts/oauth/human-access-token-header.schema.json), [claims](../../../contracts/oauth/human-access-token-claims.schema.json), and [JWKS](../../../contracts/oauth/jwks.schema.json) define the output.

**Acceptance criteria.**
- [x] Token header and claims satisfy the canonical schemas and semantic requirements.
- [x] `sub` is the Dutch App Subject, and no Human Identity ID, identifier, credential, profile field, or arbitrary claim appears.
- [x] Wrong issuer, audience, app, client, algorithm, key, type, scope, time, or security version is rejected.
- [x] JWKS exposes only matching public signing material.
- [x] Production-like profiles fail without an external self-checked signer and never generate an ephemeral key.
- [x] Refresh is absent from metadata and every token response.

**Depends on.** W-5.

## W-7 — Enforce native DPoP and durable replay protection

**Summary.** Dutch native tokens must be bound to a client-held proof key. Resource use validates the proof’s key, signature, target, method, time, nonce, token hash, and replay identity. Replay state survives restart. This completes the sender-constrained token behavior.

**Type.** AFK.

**Status.** Complete and independently accepted. The clean gate passed with 329 unit, 289 PostgreSQL integration, and 8 contract tests at 92.93% line and 80.12% branch coverage; contract bundle sha256 `7bb76067a0e2e5ea0efd1e4aca981c3ef3fead2abb7f9e467fadca8dadc81195`. Correctness/database and security/privacy reviews reported no critical, high, or medium findings after the W07-A–D correction cycles, the W07-E2 signer-path fix, and the end-to-end `/oauth2/token` proof.

**Work to be done.**
- Validate embedded public JWK, signature, and thumbprint binding.
- Validate normalized target URI, HTTP method, proof time, nonce, and `ath`.
- Persist replay identities with bounded retention semantics for this milestone.
- Exercise sequential, concurrent, and restart replay cases.
- Keep proof and token material out of logs and errors.

**Justification.** Work Unit 7 makes DPoP mandatory before Dutch relies on the access token.

**References.**
- **Work Unit 7** — [App Subject, access token, and DPoP](feature-implementation-plan.md#unit-7--slice-b-app-subject-access-token-and-dpop) defines the proof matrix.
- **D-7** — The native access-token profile is sender constrained.
- **Claims contract** — [human access-token claims](../../../contracts/oauth/human-access-token-claims.schema.json) defines `cnf.jkt`.

**Acceptance criteria.**
- [x] A correctly bound proof permits the intended request.
- [x] Signature, JWK, thumbprint, target, method, time, nonce, `ath`, and token-binding mismatches are rejected.
- [x] Reusing a proof `jti` is rejected sequentially, concurrently, and after restart.
- [x] Proofs for another app, token, method, or target cannot be replayed.
- [x] Diagnostics, persistence outside the replay store, and errors contain no access token or private proof-key material.

**Depends on.** W-6.

## W-8 — Activate Dutch and append one onboarding intent

**Summary.** An identity becomes active for Dutch only after every registered prerequisite is satisfied. One transaction resolves its App Subject, advances activation, and appends one logical onboarding intent. Missing evidence remains pending and emits nothing. Delivery is handled separately.

**Type.** AFK.

**Status.** Complete and independently accepted. The clean gate passed with 347 unit, 309 PostgreSQL integration, and 8 contract tests at 92.71% line and 80.10% branch coverage. The onboarding event is byte-for-byte the canonical eight-field payload; activation, App Subject and intent commit in one transaction. Correctness/database and security/privacy reviews reported no critical, high, or medium findings.

**Work to be done.**
- Evaluate the complete registered prerequisite set.
- Persist pending or active activation through expected-version writes.
- Append the canonical onboarding event and initial delivery intent in the first-activation transaction.
- Make retries and concurrent activation idempotent.
- Inject failures around state, event, delivery, and audit boundaries.

**Justification.** Work Unit 8 requires strict activation and transactional onboarding intent before relay or UMS consumption.

**References.**
- **Work Unit 8** — [activation and IAM onboarding outbox](feature-implementation-plan.md#unit-8--slice-c-activation-and-iam-onboarding-outbox) defines atomicity and idempotency.
- **D-10** — Activation remains strict and requires verified identifier, factor, recovery, and app prerequisites.
- **D-11** — The milestone publishes only one app-scoped onboarding event.
- **Event contracts** — [onboarding envelope](../../../contracts/events/iam.app-subject.onboarding-ready.v1.schema.json) and [payload](../../../contracts/events/iam.app-subject.onboarding-ready.v1.payload.schema.json) define the fact.

**Acceptance criteria.**
- [x] Missing verified identifier, usable factor, recovery evidence, or app prerequisite leaves activation pending and creates no event.
- [x] First activation creates one stable App Subject, one active activation, and one logical onboarding version.
- [x] Retry and concurrency create no additional subject, activation, or logical onboarding version.
- [x] Failure at any boundary rolls back activation and publish intent together.
- [x] The event validates against the canonical contract and contains only the app-scoped allowlist.
- [x] No global identity lifecycle integration event is created.

**Depends on.** W-1, W-5, W-7.

## W-9 — Relay onboarding and expose the repair snapshot

**Summary.** IAM must deliver onboarding with at-least-once semantics and expose a privileged repair view. Publishing occurs outside the state transaction, so a crash before acknowledgement causes redelivery. The snapshot is authenticated, app-bound, bounded, and unable to enumerate another app. This completes IAM’s producer side.

**Type.** AFK.

**Status.** Complete and independently accepted. The clean gate passed with 360 unit, 319 PostgreSQL integration, and 8 contract tests at 92.48% line and 80.16% branch coverage. The relay proves at-least-once delivery with lease recovery, and the snapshot is app-bound, keyset-paged and non-enumerating. Correctness/database and security/privacy reviews reported no critical, high, or medium findings.

**Work to be done.**
- Claim bounded delivery batches using durable leases.
- Publish through a transport port and acknowledge only after success.
- Recover expired leases and quarantine bounded failure classes safely.
- Implement the registered-workload snapshot query with cursor and page limits.
- Exercise crash, restart, duplicate, app-mismatch, authorization, and cursor cases.

**Justification.** Work Units 8 and 11 require durable delivery and app-scoped reconciliation.

**References.**
- **Messaging model** — [persistence and transaction model](feature-implementation-plan.md#persistence-and-transaction-model) defines lease, publish, and acknowledgement behavior.
- **D-9** — Immutable facts and mutable delivery records have separate lifecycles.
- **Snapshot contract** — [OpenAPI](../../../contracts/http/iam-onboarding-snapshot.openapi.yaml) and [response schema](../../../contracts/http/onboarding-snapshot-response.schema.json) define authorization and output.

**Acceptance criteria.**
- [x] Publish followed by a crash before acknowledgement is redelivered.
- [x] Restart and lease recovery preserve the immutable event.
- [x] Attempts, acknowledgement, and quarantine transitions remain bounded and concurrency safe.
- [x] An authenticated Dutch workload reads only Dutch onboarding records with stable cursor behavior.
- [x] Missing scope, wrong audience, credential/app mismatch, malformed cursor, or another app yields a safe non-enumerating response.
- [x] Snapshot responses, errors, logs, and metrics contain no global identity, identifier, credential, or token.

**Depends on.** W-8.

## W-10 — Pin Dutch mapping and profile contracts

**Summary.** Dutch must own concrete mapping-event and profile HTTP contracts before UMS code consumes or serves them. This item defines each shared format once so later work cannot invent divergent shapes. IAM’s imported bundle remains read-only. The contracts are closed and privacy negative by construction.

**Type.** AFK.

**Status.** Complete and independently accepted as Dutch-owned contracts in the Dutch repository. The contract gate passed with 0 validation issues and 10/10 contract tests. The UMS provider publishes a separate `ums.profile.state-changed.v1` stream; the mapping contract is Dutch-owned and not an alias (see `capabilities/work/decisions/onboarding-contract-ownership.yaml`). The mapping payload is exactly six app-scoped fields inside the pinned IAM envelope, the profile HTTP surfaces are closed and non-enumerating, and the legacy `iam.identity.verified.v1` / `ums.member.mapping.changed.v1` contracts are removed. The contract/privacy review reported no critical, high, or medium findings.

**Work to be done.**
- Author `dutch.member-profile.mapping-changed.v1` with the exact closed payload.
- Author profile-state required, provisioning, and ready responses.
- Author `/api/v1/me` profile-required and ready responses.
- Add valid and forbidden-field fixtures for app subjects, global IDs, identifiers, credentials, and tokens.
- Pin the IAM bundle version and digest as immutable consumer input.

**Justification.** Work Units 9–11 share Dutch mapping and profile formats, so one authoring item must pin them before every consumer.

**References.**
- **Contract ownership** — [contract ownership and publication](feature-implementation-plan.md#contract-ownership-and-publication) assigns these formats to Dutch.
- **Event contract** — [event contracts](feature-implementation-plan.md#event-contracts) defines the exact mapping payload.
- **HTTP contract** — [HTTP contracts](feature-implementation-plan.md#http-contracts) defines profile-required and ready behavior.
- **D-13** — UMS exposes profile state separately from the gated profile resource.
- **Imported primitives** — the [shared event envelope](../../../contracts/events/event-envelope.schema.json) and [error envelope](../../../contracts/http/error-envelope.schema.json) remain canonical IAM input.

**Acceptance criteria.**
- [x] The mapping payload is exactly `appRegistrationId`, `appSubject`, `memberId`, `mappingVersion`, `profileState`, and `lifecycleState` inside the shared envelope.
- [x] Profile state returns only the permitted state and safe retry guidance.
- [x] `/api/v1/me` returns `profile_required` until ready and a Dutch-owned Member Profile afterward.
- [x] No HTTP contract exposes App Subject, Human Identity ID, identifier, credential, code, or token.
- [x] Valid fixtures pass and every forbidden or undeclared-field fixture fails for the asserted reason.
- [x] W-11 through W-13 consume these exact contracts without alternate local schemas.

**Depends on.** W-9.

## W-11 — Create one UMS Member Profile per App Subject

**Summary.** Dutch UMS consumes the IAM event idempotently in its own database. One transaction creates the mapping, Member Profile, inbox/checkpoint effect, and Dutch mapping event. Duplicate delivery is harmless, while conflicting reuse is quarantined. UMS never reads IAM persistence.

**Type.** AFK.

**Status.** Complete and independently accepted **in the Dutch reference adapter** (`dutch/services/ums`, non-production per ADR 0009). The UMS gate passed with 18 tests, 0 failures and 0 skipped (JDK 21, PostgreSQL 16 Testcontainers). App-scoped profiles, a producer-keyed inbox with fingerprint, durable quarantine, transactional consumption and pinned-contract mapping events are proven. Correctness/privacy review reported no critical, high, or medium findings. Reorder/gap handling and checkpoint monotonicity are recorded as W-13 delivery-fault work.

**Work to be done.**
- Add inbox, fingerprint, checkpoint, App Subject mapping, profile, and mapping-outbox persistence.
- Validate IAM input against the pinned read-only bundle.
- Commit all local effects in one transaction.
- Handle duplicate, conflict, gap, reorder, rollback, concurrency, and restart cases.
- Add privacy-safe quarantine records and diagnostics.

**Justification.** Work Unit 9 is the independent consumer that completes the exactly-once business effect over at-least-once delivery.

**References.**
- **Work Unit 9** — [Dutch UMS migration and consumer](feature-implementation-plan.md#unit-9--dutch-ums-forward-migration-and-consumer) defines migration, transaction, and fault outcomes.
- **Producer contract** — [onboarding event](../../../contracts/events/iam.app-subject.onboarding-ready.v1.schema.json) is immutable imported input.
- **Consumer contracts** — W-10 pins the Dutch mapping event and profile formats.

**Acceptance criteria.**
- [x] First delivery creates exactly one mapping, Member Profile, inbox record, checkpoint effect, and logical mapping event.
- [x] Same producer/event ID and payload succeeds without another business effect.
- [x] Same producer/event ID with different payload is quarantined without modifying profile or mapping.
- [x] Distinct valid events for the same app subject preserve one profile and legal monotonic mapping behavior.
- [x] Concurrency, rollback and restart tests satisfy the defined outcomes; reorder/gap and checkpoint monotonicity are explicitly deferred to W-13.
- [x] UMS persistence, events, quarantine, logs, errors, and reports contain no global identity, identifier, credential, code, or token.
- [x] Database-role tests prove UMS cannot read IAM schemas.

**Depends on.** W-9, W-10. Production consumer parity is owned by UMS W-6/W-18 (see `capabilities/work/registry.yaml`).

## W-12 — Serve honest profile-required and ready states

**Summary.** Dutch clients need an authenticated answer while onboarding is delayed. Profile state remains required until the UMS transaction commits, and the profile resource returns a standard conflict during that interval. Once ready, both reflect the committed profile. Correlation remains safe and consistent.

**Type.** AFK.

**Work to be done.**
- Add the authenticated profile-state query.
- Gate the profile resource on committed readiness.
- Echo valid bounded correlation IDs and replace missing or invalid values.
- Exercise authentication, delay, readiness, correlation, error, and privacy cases.
- Capture logs to verify correlation without identity leakage.

**Justification.** Work Unit 10 requires an honest delayed-provisioning experience rather than synchronous-profile fiction.

**References.**
- **Work Unit 10** — [profile-required and ready HTTP](feature-implementation-plan.md#unit-10--dutch-profile-required-and-ready-http) defines controller and security outcomes.
- **D-13** — Profile state and the gated profile resource are separate surfaces.
- **Consumer contract** — W-10 pins both Dutch HTTP shapes.

**Acceptance criteria.**
- [ ] Before UMS commit, state is `PROFILE_REQUIRED` and `/api/v1/me` returns `409` with `error.code=profile_required`.
- [ ] After commit, state is `PROFILE_READY` and `/api/v1/me` returns the contracted Member Profile.
- [ ] `PROFILE_PROVISIONING` appears only when a real accepted-but-incomplete workflow exists.
- [ ] Valid correlation IDs are echoed; missing or invalid values are replaced with bounded opaque values.
- [ ] Authentication failures and application errors use the standard safe envelope.
- [ ] Responses and logs contain no App Subject, Human Identity ID, identifier, credential, code, or token.

**Depends on.** W-10, W-11.

## W-13 — Prove delivery faults and snapshot repair end to end

**Summary.** The portfolio journey must converge under expected at-least-once faults. Test-only transport connects IAM and Dutch without choosing production infrastructure. Lost acknowledgement duplicates safely, downtime preserves intent, and lost delivery repairs through the app-scoped snapshot. Every journey ends with one Dutch profile while another app remains isolated.

**Type.** AFK.

**Work to be done.**
- Connect IAM and Dutch through test-only transport adapters.
- Exercise normal, delayed, duplicate, reordered, lost-ack, UMS-down, and lost-delivery cases.
- Add bounded checkpointed snapshot reconciliation in UMS.
- Restart both services at meaningful fault points.
- Assert cross-app isolation and privacy throughout.

**Justification.** Work Unit 11 defines convergence, rather than one happy delivery, as the vertical-slice acceptance condition.

**References.**
- **Work Unit 11** — [relay, reconciliation, and portfolio journey](feature-implementation-plan.md#unit-11--relay-reconciliation-and-portfolio-journey) defines the outside-in journeys.
- **Resilience posture** — [on-call resilience](feature-implementation-plan.md#on-call-resilience-posture) defines outage, duplicate, quarantine, and repair expectations.
- **Producer and consumer contracts** — W-9 and W-10 pin every cross-service surface used here.

**Acceptance criteria.**
- [ ] The deterministic identity completes exact-redirect, S256, signed-token, and DPoP authorization before Dutch activation.
- [ ] Delayed or unavailable UMS keeps the client in `PROFILE_REQUIRED` without losing onboarding intent.
- [ ] Duplicate and publish-before-ack delivery converge on one profile and one logical mapping version.
- [ ] Lost delivery is repaired from the authenticated Dutch-scoped snapshot.
- [ ] Reorder, gap, process restart, and retry cases follow pinned checkpoint and quarantine rules.
- [ ] Another app cannot read Dutch snapshot data or receive a correlatable Dutch subject.
- [ ] Every successful journey reaches `PROFILE_READY` with one profile and no privacy canary outside IAM.

**Depends on.** W-2, W-9, W-11, W-12; `ums/W-18` (real Dutch consumer journey) and the UMS Slice C provider gates. Reference-adapter tests do not close this item.

## W-14 — Assemble development-milestone evidence and reviews

**Summary.** The final item assembles executable evidence for the entire slice. It reruns clean builds, migrations, contracts, coverage, privacy, dependency, secret, and diff checks. Independent findings return to their owning work item. The result remains a development proving milestone.

**Type.** AFK; HITL only if repository policy does not identify an approved dependency vulnerability scanner.

**Work to be done.**
- Run complete clean IAM and Dutch verification suites.
- Rehearse every required empty and retained-snapshot migration.
- Rebuild the contract bundle twice and verify the digest and Dutch pin.
- Scan logs, reports, events, quarantine, persistence snapshots, and APIs for privacy canaries.
- Obtain independent Java/Spring, database, code-quality, and security reviews.
- Route findings to their owning work item and repeat affected gates.

**Justification.** Work Unit 12 and the Definition of Done require auditable evidence and no unresolved critical or high findings.

**References.**
- **Work Unit 12** — [release-candidate evidence](feature-implementation-plan.md#unit-12--release-candidate-evidence-and-reviews) defines final commands and review disciplines.
- **Definition of Done** — [milestone-wide acceptance](feature-implementation-plan.md#definition-of-done) defines the evidence set.
- **D-14** — The result must be labelled a development proving milestone, not production ready.

**Acceptance criteria.**
- [ ] IAM clean checks, contract tests, integration tests, portfolio tests, and coverage verification pass.
- [ ] Dutch UMS clean checks and integration tests pass.
- [ ] Aggregate line and branch coverage are each at least 80%, with explicit security-sensitive race and replay scenarios.
- [ ] Contract bundles are reproducible and Dutch’s pinned digest matches its consumed archive.
- [ ] Static, dependency-policy, approved vulnerability, SBOM, secret, privacy, migration, and scoped-diff checks pass, or the absent approved vulnerability scanner is reported as a named unresolved integration gap rather than silently substituted.
- [ ] No critical or high review finding remains unresolved.
- [ ] The handoff lists changed files, exact commands and results, and remaining gaps, and labels the result a “development proving milestone.”
- [ ] No commit, push, registry publication, or cloud selection occurs.

**Depends on.** W-1, W-2, W-3, W-4, W-5, W-6, W-7, W-8, W-9, W-10, W-11, W-12, W-13.

## Named gaps

- **Deployment and production operations.** Tracked separately in [deployment work items](deployment-work-items.md) as `DEP-1`…`DEP-6`.

- **Dependency vulnerability scanning.** Locking, dependency verification, policy checks, and an SBOM exist, but no approved vulnerability scanner is configured. W-14 records this as HITL if repository policy still provides no approved choice.
- **Dutch-owned contract inventory.** W-10 must inspect current Dutch contracts and reconcile existing shapes inside the pinned privacy boundary.
- **Retained Dutch UMS migration snapshot.** If none exists, W-11 records that fact and tests the oldest reproducible checked-in baseline rather than inventing history.
- **Production transport and key custody.** The milestone proves ports and fail-closed wiring; provider selection and operations remain with cloud reconciliation.
- **Factor and recovery depth.** W-2 supplies only the normal-model evidence needed for strict activation; broader lifecycle behavior belongs to later slices.
- **Production operational gates.** Backup/restore, capacity, SLOs, alerts, deployment, and incident runbooks remain outside this development milestone.
- **Cross-repository harness convention.** W-13 must use the current supported IAM and Dutch build layouts without production coupling or shared persistence.

## Cut for Scope

This is work the work item excludes, not work deferred for lack of evidence. There is no trigger that reopens an entry here; the recorded boundary already settled it.

- **Issue refresh tokens and manage refresh-token families.** D-6 excludes refresh through Slice C, so metadata and responses must not advertise it.
- **Provide OIDC discovery, ID tokens, UserInfo, or arbitrary claims.** The milestone publishes OAuth metadata and a closed access-token profile only.
- **Publish global identity lifecycle or bridge events.** D-11 permits only the app-scoped onboarding event after activation.
- **Choose or deploy brokers, DLQs, KMS/HSMs, distributed rate limiting, cloud databases, regions, alerts, or production topology.** Those decisions belong to the separate cloud-solutions work.
- **Implement Identity Platform Slices D–H.** Expanded factor/recovery, sessions, refresh, delegation, workload identity, lifecycle administration, and production hardening are outside Foundation through Slice C.
- **Integrate Midas, Jarvis, or another product.** This milestone proves reusable portfolio contracts through Dutch only.
- **Modify Ledger, Gateway, or mobile implementations.** Their ownership is outside this plan unless a separately approved additive contract requires it.
- **Add generic administration, dynamic client registration, a remote contract registry, generated SDKs, or separate IAM deployables.** No current acceptance journey requires them.
- **Build legacy event compatibility or live-account migration machinery.** There is no live identity or consumer population requiring dual behavior.
- **Choose production verification delivery UX or an SMS/email provider.** Channel and abuse-policy work belongs to a later product and security slice.
- **Commit, push, open a pull request, or publish remotely.** The execution boundary explicitly excludes external mutation.
