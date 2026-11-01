Type: grilling
Status: resolved
Assignee: Codex
Parent: [Specify the shared first-party Identity Platform](../map.md)

# Define Identity, app, trust, and privacy boundaries

## Question

What exact invariants govern Human Identity, Verified Identifiers, App Activations, first-party trust, cross-app visibility, profile ownership, and the boundary between centralized identity and application-owned authorization?

## Answer

One Human Identity is intended to represent one natural person across every first-party application. Shared/family identities are prohibited. Multiple devices, Verified Identifiers, Authentication Factors, Platform SSO Sessions, App Sessions, App Subjects, and App Activations attach to that one principal. Duplicate Human Identities can still arise when no verified evidence connects registrations; the platform prevents them where evidence permits and resolves them only through explicit recovery/linking—not probabilistic or silent merging.

A normalized verified email or E.164 phone is globally unique among active Human Identities. A Human Identity may own multiple identifiers and factors. Policy separately marks login, communication, and recovery eligibility; removing the last recovery-capable method requires a safe replacement or an explicit unrecoverable-account decision. Unsupported identifier types fail closed. Email and phone are the initial implementations of the controlled Typed Verified Identifier model, while passkeys remain Authentication Factors rather than identifiers.

IAM keeps its global Human Identity ID internal and presents a stable, application-specific App Subject to ordinary apps. IAM knows all App Activations, but an ordinary app sees only its own. A separately approved umbrella experience may receive cross-app activation visibility through a purpose-bound scope, user-facing disclosure, audit evidence, and limited retention.

An App Activation governs IAM permission to issue credentials for one app and has four states:

- `PENDING_PREREQUISITES` — authentication succeeded, but a declared entry prerequisite such as terms, invitation, eligibility, or approval remains unmet.
- `ACTIVE` — IAM may authorize the app, subject to its Product Security Policy.
- `SUSPENDED` — IAM temporarily blocks this app without disabling the Human Identity or other apps.
- `DEPARTED` — the person left the app; app sessions are revoked and deliberate reactivation is required.

App Activation is not profile readiness. An activation may be `ACTIVE` while an app-owned profile is still being created or while the app independently blocks domain use. Product profiles, subscriptions, roles, memberships, balances, bans, and other domain authorization remain application-owned.

IAM tokens contain only authentication context, typed subject, audience, scopes, assurance, session, and relevant activation/security state. First-party status does not grant unrestricted data access: raw verified identifiers require an explicit purpose, narrow service authorization, minimal fields, audit, and retention policy. Credentials and refresh tokens never cross their authorized IAM/client boundary.

Client/app compromise is isolated through application audiences, client-bound refresh families, scopes, and app-specific revocation. Global Identity lock is reserved for compromise of the shared Human Identity, identifiers, factors, or platform authentication context.
