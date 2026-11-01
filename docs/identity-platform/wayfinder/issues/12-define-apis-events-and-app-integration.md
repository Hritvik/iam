Type: grilling
Status: resolved
Assignee: Codex
Parent: [Specify the shared first-party Identity Platform](../map.md)
Blocked by: 05, 07, 08, 09, 10, 11

# Define APIs, events, and first-party app integration

## Question

What versioned OAuth/OIDC metadata, HTTP APIs, administrative interfaces, lifecycle events, error envelopes, correlation rules, idempotency behavior, compatibility policy, and onboarding contract let independent first-party apps integrate without sharing databases or product-domain data?

## Decision

### Integration principle

- IAM exposes standards-based OAuth/OIDC endpoints, narrowly scoped platform APIs, reviewed administrative APIs, and immutable PII-free lifecycle events. It never exposes persistence schemas or a generic internal-object API.
- Each application owns its own profile and domain authorization. Dutch UMS owns Dutch Member Profiles; Midas, Jarvis, and future apps own their equivalents. There is no automatically synchronized portfolio-wide display profile.
- IAM addresses an app through its App Registration and App Subject. Ordinary app contracts never expose the global Human Identity identifier or another app's subject/activation.
- A future optional “copy account card into this app” journey requires explicit user action and creates app-owned values. It does not establish silent ongoing profile synchronization.

### Standards endpoints and metadata

Each environment publishes one HTTPS issuer with OIDC Discovery and OAuth Authorization Server Metadata, including exact supported endpoints, code challenge methods, response/grant types, token endpoint authentication methods, signing algorithms, DPoP/mTLS capabilities, revocation, introspection where enabled, token exchange where enabled, and logout support.

Required protocol surfaces include authorization, token, JWKS, revocation, RP-initiated logout, back-channel logout registration/processing, and standards-defined protected-resource metadata for registered APIs. Token exchange is advertised only when implemented and remains policy-denied absent a registered Delegation Workflow.

Dynamic client registration, password grant, implicit flow, arbitrary UserInfo claims, and an unauthenticated introspection interface are not exposed. UserInfo is absent by default; an app needing IAM-owned personal data requires a separate purpose/field/retention decision.

### Platform HTTP APIs

Non-protocol APIs are versioned under `/platform/v1` for user/security journeys and `/internal/v1` for authenticated workloads. The authoritative OpenAPI defines, at minimum:

- current security/account summary, Verified Identifier metadata, factor lifecycle, recovery-code regeneration, session/device listing and scoped revocation;
- app activation/prerequisite status, app departure/reactivation initiation, privacy export, global deletion request/cancellation/status;
- app onboarding/profile-readiness acknowledgement and reconciliation snapshot;
- registered prerequisite assertions, security-version projection repair, logout delivery acknowledgement, and narrowly scoped identifier-reference operations where a separately approved product flow needs them;
- administrative security lock/status, bounded lifecycle action, delivery/reconciliation status, manifest reconciliation, and credential/client/workflow emergency disablement.

APIs expose task-specific DTOs and commands, not CRUD over Identity, sessions, factors, tokens, audit rows, or encrypted identifiers. State-changing operations require authenticated authority, schema validation, an idempotency key, expected version where state already exists, and reason/purpose where administrative.

### Response and error contract

Successful JSON responses use `{ "data": ... }`. Errors use:

```json
{
  "error": {
    "code": "stable_machine_code",
    "message": "safe human-readable message",
    "details": [],
    "correlationId": "opaque-correlation-id"
  }
}
```

`details` is optional, schema-bound, and contains only safe field/retry guidance. It never contains raw identifiers, existence disclosures, database constraints, tokens, stack traces, policy internals, or another app's state.

Use protocol-defined OAuth/OIDC errors on standards endpoints. Platform APIs consistently use `400` malformed input, `401` absent/invalid authentication, `403` authenticated but unauthorized, non-enumerating `404` where resource privacy requires it, `409` stale/idempotency/state conflict, `422` valid shape but unsatisfied semantic rule, `429` with `Retry-After`, retryable `503` with `Retry-After`, and generic `500`. Recovery/login/identifier responses remain non-enumerating even when internal causes differ.

### Correlation, idempotency, and concurrency

- Accept a syntactically bounded `X-Correlation-Id` from trusted first-party edges; otherwise generate one. Return it in response headers and safe error envelopes and propagate it through outbox correlation metadata. It is not an authorization input, resource ID, or place for user data.
- Generate a new causation ID for each accepted command/event. Trace baggage is allowlisted and contains no identifiers, tokens, codes, or profile fields.
- State-changing non-protocol commands require a UUID `Idempotency-Key`, scoped to caller, operation, and target. Exact retries return the recorded safe outcome; reuse with a different canonical request returns `409 idempotency_key_reused`.
- Use `If-Match` or an explicit expected version for changes to existing security/lifecycle state. Stale updates fail without partial effects.
- Token endpoint replay and authorization-code/refresh rotation obey protocol artifact semantics rather than generic HTTP idempotency; no idempotency store may reproduce a bearer secret.

### Lifecycle event envelope

All events use the shared immutable envelope with event ID, event type, schema version, occurred time, producer, environment, opaque aggregate type/ID/version, correlation ID, causation ID, and allowlisted payload. Event delivery is at least once; aggregate version is ordered only within its documented stream.

IAM event families include app-scoped variants of:

- `iam.app-subject.onboarding-ready.v1` (the production successor/clarification of Dutch Slice 1's `iam.identity.verified.v1` intent);
- `iam.app-activation.changed.v1`;
- `iam.identity.security-version-changed.v1`, routed/projected as an app-scoped subject event;
- `iam.app-session.revoked.v1` where a resource needs immediate app-local enforcement;
- `iam.app-subject.deletion-pending.v1`, `deletion-cancelled.v1`, and `deleted.v1`;
- registered workload/credential/delegation lifecycle facts needed by affected resources.

The canonical onboarding event payload contains only App Registration ID, App Subject, activation ID/state/version, onboarding reason/version, required profile state, and timing/correlation metadata. It contains no global Human Identity ID, email, phone, factor, token, session secret, device fingerprint, or cross-app activation.

For compatibility with the initial Dutch vertical slice, `iam.identity.verified.v1` may exist only as a time-bounded app-routed v1 contract whose `identityId` field is defined as Dutch's opaque app subject—not the global Human Identity ID. The implementation handoff must either rename before production to `iam.app-subject.onboarding-ready.v1` or document a dual-publish/migration period; the misleading name must not become the long-term portfolio contract.

### App onboarding and profile readiness

1. A human completes IAM verification/authentication for a specific authorization request.
2. IAM creates or resolves Human Identity, App Subject, and App Activation under the initiating app's policy.
3. The same transaction commits the app-scoped onboarding-ready outbox event.
4. The app's profile service consumes it idempotently and enforces a unique profile/mapping per App Subject.
5. The app commits profile creation/mapping and its own PII-free mapping/profile-state outbox event in one local transaction.
6. The app reports/project-publishes `PROFILE_READY`; until then its gateway/resource returns the standard `profile_required` state without denying use of unrelated apps.
7. Duplicate, delayed, reordered, or replayed events cannot create another profile. Reconciliation compares app-scoped subject/activation versions through an authenticated snapshot contract.

For Dutch, UMS performs steps 4–6 and emits a Dutch member-mapping event containing App Subject, Dutch Member ID, mapping/profile version, lifecycle state, correlation, and causation. No other app must depend on Dutch UMS.

Profile status endpoints provide `PROFILE_REQUIRED`, `PROFILE_PROVISIONING`, `PROFILE_READY`, and safe retry/error state as app-owned status. `202` may represent asynchronous provisioning; an authenticated `409 profile_required` or successful status response guides clients without leaking another identity's existence. IAM does not falsely mark a product profile ready merely because delivery succeeded.

### Compatibility policy

- OpenAPI, OAuth metadata, manifest schemas, JSON Schemas, AsyncAPI, fixtures, and conformance tests are versioned artifacts and the contract source of truth. Generated models are replaceable implementation details.
- Additive optional fields are compatible. Consumers ignore unknown fields but reject invalid known fields. A removed field, changed type, tightened previously accepted enum, changed security meaning, changed subject interpretation, or changed event semantics requires a new version.
- Incompatible event migration uses an explicit new event type/version, consumer readiness evidence, bounded dual publish/backfill where needed, and observed retirement. Never reinterpret stored v1 events as v2.
- Support current and immediately previous stable API/contract versions for a declared migration window; security fixes may shorten support through a documented emergency process.
- CI validates producer and consumer fixtures, negative PII/secret rules, error envelopes, duplicate/reorder/gap handling, token type confusion, authorization, and backward compatibility.

### App onboarding checklist

A new first-party app cannot enter production until it has:

- approved App/Client/Resource Registration manifests and Product Security Policy;
- exact redirect/logout endpoints and credential/sender-constraint setup;
- OAuth/OIDC discovery, PKCE, state/nonce, issuer/audience/type validation, and key-rotation tests;
- app-scoped profile/onboarding consumer with transactional inbox/outbox, uniqueness, delay, duplicate, gap, deletion, and reconciliation tests;
- resource-owned scopes and domain authorization with no reliance on token product roles;
- standard errors, correlation, rate limits, redaction, no-PII fixtures, and log/trace scanning;
- session/logout, recovery restriction, step-up, outage, and security-version behavior tests;
- owners, alerts, runbooks, retention/deletion behavior, and staged promotion evidence.

No checklist exception may be satisfied by direct IAM database access, copying raw identifiers into the app, or sharing another app's App Subject.
