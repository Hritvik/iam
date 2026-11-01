Type: grilling
Status: resolved
Assignee: Codex
Parent: [Specify the shared first-party Identity Platform](../map.md)
Blocked by: 01, 04, 08

# Design identity lifecycle, privacy, and administration

## Question

What exact app activation/departure, identifier change, lock, recovery, global deletion, retention, export, operator/support access, audit, cross-app disclosure, and downstream anonymization semantics preserve privacy without erasing application-owned evidence?

## Decision

### Identity and activation lifecycle

- A Human Identity begins only after verified-identifier proof and moves through explicit `ACTIVE`, `SECURITY_LOCKED`, `DELETION_PENDING`, and `DELETED` lifecycle states. Recovery restriction is separate state and never masquerades as ordinary `ACTIVE` assurance.
- App Activations retain the settled `PENDING_PREREQUISITES`, `ACTIVE`, `SUSPENDED`, and `DEPARTED` states. Transitions are explicit, reason-coded, idempotent, versioned, audited, and committed with their PII-free outbox event.
- Leaving one app revokes that app's sessions and refresh families and transitions only its activation to `DEPARTED`. It does not delete the Human Identity, reveal other activations, or change another app's profile/data.
- Reactivation after departure is a deliberate authorization journey. It re-evaluates current prerequisites, disclosure, security policy, and app-owned profile readiness; it does not silently restore old product authority.
- App suspension is app-scoped. Global security lock is reserved for compromise of shared identity, identifiers, factors, recovery, or platform authentication authority.

### Identifier and factor changes

- Add, promote, demote, replace, or remove operations require recent Strong authentication except during the governed restricted recovery journey.
- A new identifier is verified before attachment and atomically checked for global uniqueness. Notifications go to existing recovery channels without exposing the new identifier unnecessarily.
- Risk policy applies cooldowns before a newly added identifier becomes the sole recovery authority or enables sensitive actions. The final safe recovery method or usable factor cannot be removed without replacement.
- Identifier reassignment between Human Identities is never automatic. Conflict resolution requires evidence-backed recovery/linking and preserves an audit trail without exposing one identity to the other.
- Security-relevant changes revoke affected sessions/families, advance the security version where shared authority changed, and emit only typed PII-free lifecycle facts.

### App departure and product data

- IAM owns activation departure; the product owns profile closure, balances, memberships, content, regulatory records, and domain deletion/anonymization.
- IAM emits an app-scoped departure event carrying App Subject, activation/version, reason class, effective time, correlation, and causation. It contains no Human Identity ID, identifier, credential, token, profile field, or free-text reason.
- Products acknowledge/process departure idempotently under their own retention policy. Failure does not restore IAM authority; reconciliation keeps the delivery visible until resolved.
- A product may retain evidence required by law, fraud prevention, accounting, dispute handling, or security, but it must disconnect retained evidence from active login authority and minimize or pseudonymize it where lawful.

### Global deletion

- Global deletion requires recent Strong authentication and a clear portfolio-wide consequence review. High-risk/recovered sessions must first satisfy their restrictions.
- Confirmation immediately changes the identity to `DELETION_PENDING`, revokes every Platform SSO Session and refresh family, advances the security version, blocks new authorization, and emits an app-scoped deletion-pending event to every activation.
- The reversible period is 30 days. Governed self-service recovery during that period may cancel deletion, re-establish factors, and cause a new lifecycle version/event; applications receive cancellation only if they need it to pause irreversible product erasure.
- After the deadline, a durable finalizer destroys or irreversibly pseudonymizes verified identifiers, Authentication Factor material, recovery material, sessions, grants, and unnecessary operational metadata. The identity becomes `DELETED`; stable identifiers are never reassigned or reused as identity records.
- IAM retains only minimal pseudonymous audit/security evidence required by declared retention policy. It must not retain raw email/phone, credential material, token values, WebAuthn secrets, recovery evidence, or operator notes merely for convenience.
- Each product receives an app-scoped deletion-final event and applies its own deletion, anonymization, or lawful-retention policy. IAM does not directly access or mutate product databases and cannot promise erasure of evidence a product must lawfully retain.
- Delivery is at least once and reconciled. A downstream outage delays downstream processing but not IAM's authoritative revocation or finalization. Operational status distinguishes requested, delivered, acknowledged, completed, retained-with-policy, and failed states without centralizing product data.

### Export and transparency

- IAM provides an authenticated export of the user's IAM-owned data: identifier types and appropriately protected/display-safe values, verification/lifecycle dates, factors and states without secrets, devices/sessions, app activations, security history, and administrative actions that may lawfully be disclosed.
- Product data exports remain product-owned. The IAM privacy surface links or directs the user to each activated product rather than aggregating product profiles into IAM.
- Export generation requires recent Strong authentication, is asynchronous, encrypted at rest, short-lived, download-limited, audit-recorded, and never sent as an email attachment. Download authorization is separate from notification.

### Operator and support model

- There is no operator impersonation, token minting for a user, credential viewing, raw session takeover, direct production database editing, or unrestricted identifier search.
- Administrative capabilities are task-specific: security lock/unlock, app suspension, credential/client disablement, delivery retry, deletion workflow status, and evidence-backed recovery actions. Every capability has least-privilege role, reason code, case reference, bounded target/scope, audit, and notification policy.
- Raw identifier lookup, when operationally unavoidable, is isolated behind a purpose-bound audited capability with exact-match input, rate limiting, masked output, and short retention. Ordinary support views use opaque references.
- Break-glass access is time-limited, strongly authenticated, narrowly scoped, alerted, and retrospectively reviewed. It does not bypass cryptographic or recovery invariants.
- Manual identity recovery does not launch while the platform has only one operator. Self-service passkeys, authenticated-device recovery, verified recovery channels, and recovery codes are available; failure of all of them leaves the old identity inaccessible.
- Manual recovery can be enabled only when two genuinely independent authorized approvers and the previously specified evidence, cooldown, notification, Recovery Grant, and immutable audit controls are operational. Automation or coding agents cannot serve as the independent human approver.

### Cross-app disclosure and audit

- Ordinary apps see only their App Subject and activation. Approved umbrella surfaces may list cross-app activation names/statuses only through a purpose-bound scope, explicit disclosure, minimal retention, and audit; they receive no product activity, profile, balance, role, or raw identifier.
- Audit is append-only at the application layer, integrity-protected, reason-coded, correlation/causation linked, access-controlled, and separately retained from operational records. Audit payload schemas use allowlists and prohibit tokens, credentials, challenges, recovery evidence, raw identifiers unless a narrowly defined protected audit requirement explicitly demands one.
- Privacy requests, exports, administrative reads/actions, identifier access, deletion transitions, app lifecycle changes, locks, recovery, and break-glass use are auditable. Audit access itself is audited.
