Type: grilling
Status: resolved
Assignee: Codex
Parent: [Specify the shared first-party Identity Platform](../map.md)
Blocked by: 04, 05, 07, 08, 09, 10, 11, 12, 13

# Define verification and production acceptance

## Question

What TDD, contract, migration, protocol-conformance, adversarial security, privacy, concurrency, outage, recovery, load, key-rotation, multi-client, and operational evidence is required before each platform capability and the overall Identity Platform may enter production?

## Decision

### Evidence model and TDD

- Every implementation work item traces to a settled requirement and starts with an executable failing acceptance, contract, invariant, or security test. The work record retains compact RED evidence, the minimal GREEN implementation evidence, and refactor/coverage results. A test that never failed for the intended reason is not TDD evidence.
- Tests use production code paths and real protocol/persistence components at the appropriate layer. Mock-heavy tests cannot prove database concurrency, cryptography, authorization-server behavior, HTTP security filters, migrations, broker idempotency, or log redaction.
- Minimum aggregate line and branch coverage is 80%, but coverage never substitutes for scenario evidence. Identity creation, uniqueness, token issuance/validation, code/refresh consumption, replay response, recovery, security-version advancement, deletion, and outbox/inbox transaction branches require effectively complete decision coverage.
- No skipped, quarantined, flaky, or environment-disabled release test may protect a production acceptance criterion. Flakes are failures until isolated and repaired.
- Tests own their data, clock, key fixtures, issuer/environment, and cleanup. They never use production identifiers, real user data, production signing material, live SMS/email destinations, or shared mutable fixtures.

### Unit and property verification

Require deterministic unit/property tests for:

- typed identifier normalization, HMAC input/domain separation, masking, supported-type rejection, and normalization-version migration;
- assurance/policy strictest-merge evaluation, step-up/recent-auth decisions, activation prerequisites, state machines, and prohibited transitions;
- App Subject derivation/stability/isolation without exposing the Human Identity ID;
- scope/resource reduction, subject-kind and token-profile confusion, delegation workflow matching, actor preservation, and denial by default;
- token/code/challenge lifetime boundaries, clock skew, refresh-family transitions, recovery restrictions, deletion deadlines, and key overlap;
- event allowlists and explicit negative assertions for PII, credentials, secrets, tokens, device fingerprints, free text, and cross-app identifiers;
- retry/backoff bounds, error mapping, non-enumerating outcomes, canonical idempotency fingerprints, and immutable DTO/domain behavior.

Security properties use generated/adversarial inputs for Unicode, length limits, malformed encodings, JSON depth/size, algorithm/header combinations, duplicate fields, boundary times, and state-transition sequences.

### Database and migration integration

- Run service integration tests against the supported PostgreSQL major version using isolated containers or ephemeral managed databases, not an in-memory substitute.
- Rehearse migrations from empty schema and every supported released schema. Verify checksums, constraints, indexes, roles/permissions, key/normalization version backfills, expand/contract compatibility, rollback/forward-repair posture, and that a failed migration leaves recoverable state.
- Prove identifier encryption/blind-index uniqueness, concurrent duplicate registration, App Subject/profile uniqueness, authorization-code single use, OTP/recovery-code single use, refresh concurrent redemption/reuse response, optimistic version conflict, idempotency-key mismatch, deletion finalization, and security-version monotonicity.
- For every lifecycle operation, inject failures before commit, after state write, after outbox write, after commit/before response, after publish/before acknowledgement, and during consumer effect. State plus outbox/inbox behavior must match the documented transaction boundary.
- Prove database isolation with separate credentials and permission-negative tests. No IAM query or migration can resolve an application table, and no app role can read IAM ciphertext/blind indexes.
- Restore a production-shaped encrypted backup into isolation, rotate/recover required keys, apply deletion tombstones, run migrations, reconcile outbox/security projections, and measure RPO/RTO.

### OAuth/OIDC and client-profile conformance

Positive and negative suites cover every registered client profile and use an external standards/conformance suite where practical. Required evidence includes:

- exact redirect and post-logout matching; rejection of prefix, wildcard, case/encoding confusion, userinfo, fragments, open redirects, unregistered schemes, and wrong environment;
- authorization-code flow with S256 PKCE; missing/wrong/verifier-reuse/downgrade/plain challenges; state, nonce, issuer, and mix-up defenses;
- public-client rejection of secret assumptions; confidential-client `private_key_jwt` signature, audience, issuer/subject, expiry, and assertion replay; mTLS binding where applicable;
- ID-token signature/audience/nonce/auth-time/issuer validation and resource-server rejection of ID tokens;
- RFC 9068 access-token `typ`, issuer, algorithm, key, audience, lifetime, subject kind, client, scope, assurance, security version, and claim-version validation;
- DPoP signature, key thumbprint, method/URI normalization, proof time/JTI replay, nonce, `ath`, access/refresh binding, lost-key, and wrong-resource tests;
- resource indicator enforcement and rejection of multi-audience/cross-app/cross-environment/forwarded tokens;
- refresh rotation, simultaneous use, lost response, reuse/family revocation, sender mismatch, expiry, app/device/global revocation, and no raw token persistence/logging;
- logout token verification, duplicate delivery, back-channel retry, scoped/global behavior, and malicious logout denial;
- token exchange default denial, registered one-hop success, actor omission/change, scope expansion, audience change, purpose mismatch, stale assurance, recursive exchange, and refresh denial.

Authorization server metadata, discovery, JWKS, protected-resource metadata, key overlap/cache behavior, and unsupported feature advertisement are contract tested.

### Journey and adversarial security verification

Automated browser/native integration tests cover first identity bootstrap, passkey enrollment/login, verified-channel fallback, another app's SSO activation, step-up, factor/identifier management, recovery, scoped/global logout, profile delay, departure/reactivation, export, and deletion/cancellation/finalization.

Adversarial tests cover enumeration, verification flooding, OTP/recovery guessing, CSRF/login CSRF, session fixation, replay, redirect interception, XSS-sensitive browser token absence, cookie attributes, origin/RP-ID validation, WebAuthn challenge binding, credential duplication, request smuggling/header limits at the deployed edge, SSRF through registration/configuration, SQL/JSON injection, privilege escalation, cross-app correlation, workload/human confusion, administrative scope bypass, and denial-of-service amplification.

Security review includes dependency/SBOM/license and vulnerability scan, static analysis, secret scan including history/diff/artifacts, container/IaC scan after cloud reconciliation, manual threat-model review, and independent penetration review before broad public launch or after a major protocol/recovery change. Critical/high findings block release until fixed or explicitly risk-accepted by authorized governance; a sole developer cannot silently self-waive a critical identity flaw.

### Privacy and telemetry verification

- Contract fixtures, database test snapshots outside IAM, broker messages/DLQs, logs, metrics, traces, error reports, analytics, exports, support views, and API responses are scanned for seeded canary email, phone, credential, code, token, private key, and cross-app subject values.
- Verify generic behavior and timing-class controls for existent/nonexistent identifiers and recovery states. Test rate-limit keys do not reveal raw identifiers.
- Prove ordinary apps cannot request or infer another app's subject, activation, profile, session, or product activity; only the approved umbrella scope sees the minimal disclosed activation view.
- Verify exports include only IAM-owned data, require recent Strong authentication, expire, are download-limited, and exclude secret material. Verify app departure versus global deletion and lawful product retention/anonymization boundaries.
- Audit schemas, integrity evidence, access-to-audit auditing, retention jobs, operator-purpose enforcement, masking, break-glass alerting, and absence of impersonation are acceptance tested.

### Events and application onboarding

- Validate OpenAPI, JSON Schema, AsyncAPI, manifests, canonical examples, compatibility rules, size limits, and PII-negative rules in CI.
- Producer/consumer suites cover duplicate, delayed, reordered, gap, poison, incompatible-version, DLQ, replay, backlog, and reconciliation behavior.
- For every app onboarding consumer, prove one profile/mapping per App Subject under concurrent and distinct-event delivery, transactional inbox plus profile plus outbox, `PROFILE_REQUIRED/PROVISIONING/READY`, IAM/app outage, departure, security-version update, deletion, and replay after restore.
- Prove the transitional Dutch `iam.identity.verified.v1` never carries the global Human Identity ID and has an evidenced rename/retirement plan before it becomes a portfolio dependency.

### Outage, recovery, load, and operations

- Inject loss/latency/failure for IAM instances, PostgreSQL primary/failover, key service, broker, cache/rate limiter, DNS, network, email/SMS provider, object/export storage, and dependent app. Verify documented fail-closed/degraded behavior and honest client errors.
- Demonstrate that cached discovery/JWKS plus local security projections accept only valid unexpired tokens during an IAM outage; authorization, refresh, recovery, factor changes, first activation, and global revocation requests do not falsely succeed.
- Load tests cover peak authorization/token/passkey/refresh, login bursts, global revocation fanout, outbox backlog recovery, DPoP replay storage, abusive identifier traffic, database pool exhaustion, and key-service throttling. Meet SLOs with bounded queues/pools and without dropping audit/outbox facts.
- Rehearse signing/encryption/blind-index/client credential rotation, compromised-key response, expired old key, stale JWKS cache, re-encryption/reindex restart, and rollback before retirement.
- Exercise backup restore, instance/failure-domain loss, regional recovery runbook where applicable, outbox/DLQ reconciliation, deletion finalizer, emergency client/app/workload disablement, telemetry access, break glass, and alert routing. Record timestamps, result, gaps, owner, and remediation.

### Capability and production gates

A capability may enter staging only when:

1. requirements and threat boundaries trace to tests;
2. RED/GREEN/refactor evidence exists;
3. unit/property, PostgreSQL integration, contract, privacy-negative, and applicable protocol/journey tests pass;
4. migrations are compatible and forward repair is documented;
5. coverage thresholds and critical-branch expectations pass;
6. logs/metrics/errors/rate limits/runbook are present; and
7. no unresolved critical/high security defect exists.

The Identity Platform may enter production only when, additionally:

- all required first-party client profiles pass conformance and end-to-end staging journeys;
- cloud reconciliation is complete and infrastructure evidence satisfies ticket 13;
- backup/restore, key rotation, outbox/DLQ/reconciliation, failure-domain, and incident exercises meet measured objectives;
- load/capacity/cost evidence meets launch assumptions with headroom;
- an independent security review/penetration assessment is complete for the public authentication surface;
- privacy/export/deletion/operator controls and retention documentation are approved;
- immutable artifact, SBOM, dependency, configuration, contract, manifest, migration, key-generation, and environment provenance are recorded; and
- the release record names the operator, rollback/forward-repair decision owner, incident contacts, accepted risks, and next review date.

Production acceptance is evidence, not the absence of observed failure. A feature flag cannot make an untested credential, recovery, delegation, or administrative path safe.
