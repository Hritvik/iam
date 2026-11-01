Label: wayfinder:map

# Specify the shared first-party Identity Platform

## Destination

A complete, implementation-ready requirements specification and solution design for a shared Identity Platform serving Dutch, Midas, Jarvis, and future first-party applications, with settled domain language, security invariants, protocols, client profiles, lifecycle behavior, contracts, persistence, operations, verification, and a build-ready handoff.

## Notes

- Planning and design only: resolve decisions and produce specification context; do not implement the platform.
- Start from first principles. Existing IAM code is disposable evidence, not the authoritative design or technology choice.
- One Human Identity spans all first-party applications; ordinary App Activation is idempotent on first successful SSO, subject to declared prerequisites.
- Use one issuer per environment with application-specific clients, audiences, scopes, redirect policies, refresh families, and Product Security Policies.
- Support native public clients with authorization code plus S256 PKCE, confidential server web clients, browser applications through a BFF, and internal Workload Identities. Direct-token SPAs are disabled by default.
- IAM owns identities, verified identifiers, factors, authentication, recovery, sessions, OAuth/OIDC, workload principals, App Registrations, and App Activations. Applications own profiles and domain authorization.
- Shared platform SSO coexists with device-, app-, and global-revocation scopes. Valid app-bound access tokens may continue locally during an IAM outage; login, refresh, recovery, factor changes, and first activation pause.
- Email and E.164 phone are initial Verified Identifier types. Passkeys are Authentication Factors, not identifiers.
- App Registration manifests are expected to be reviewed, version-controlled, schema-validated, and reconciled through controlled automation; the exact design remains a ticket decision.
- Existing production-account migration is unnecessary because no application identity population is live.
- Consult [`CONTEXT-MAP.md`](../CONTEXT-MAP.md), [`IAM-CONTEXT.md`](../IAM-CONTEXT.md), the `grilling`, `domain-modeling`, `research`, `security-review`, `api-design`, and `backend-patterns` skills where relevant.
- Ask the human only when two or more viable choices carry material product, cost, control, or operating tradeoffs. Decide and record consequences that follow directly from settled requirements, standards, or invariants without ceremonial confirmation.

## Decisions so far

<!-- Resolved tickets are indexed here by name; detailed answers live in their tickets. -->

- [Define Identity, app, trust, and privacy boundaries](issues/01-define-identity-trust-and-privacy-boundaries.md) — One Human Identity maps to privacy-preserving App Subjects and explicit App Activations, while identifiers remain globally protected and product profiles/authorization remain application-owned.
- [Research current identity and OAuth security standards](issues/02-research-current-identity-security-standards.md) — Current BCPs require code flow, exact redirects, PKCE, resource-bound typed tokens, secure browser/native profiles, non-human workloads, and explicit rather than generic delegation.
- [Research candidate Identity Platform approaches](issues/03-research-identity-platform-options.md) — Complete products reduce IAM feature build-out, while SAS/Hydra-style protocol engines better preserve bespoke PII and event boundaries at the cost of substantially more product and operations work.
- [Define authentication, assurance, and recovery](issues/04-define-authentication-assurance-and-recovery.md) — Passkey-first, passwordless authentication uses structured assurance, deterministic step-up, protected verified-channel bootstrap, and recovery that revokes prior authority without support impersonation or silent identity reassignment.
- [Design App Registration and Product Security Policy](issues/05-design-app-registration-and-security-policy.md) — Reviewed manifests define constrained client/resource profiles and inheritable security policy, reconcile into an isolated durable registry, and promote through risk-tiered approvals with explicit drift, rotation, emergency, and retirement controls.
- [Select the Identity Platform and technology stack](issues/06-select-platform-and-technology-stack.md) — The platform is a Java/Spring/PostgreSQL modular IAM monolith using Spring Authorization Server, with a local transactional outbox, minimal operational variety, and language-neutral contracts for independently implemented applications.
- [Design tokens, claims, and resource validation](issues/07-design-tokens-claims-and-resource-validation.md) — Single-resource typed JWT access tokens, opaque rotating refresh families, mandatory native DPoP, pairwise app subjects, strict local validation, and a PII-free security-version projection prevent confusion and support outage-tolerant urgent revocation.
- [Design SSO, sessions, refresh families, and revocation](issues/08-design-sso-sessions-and-revocation.md) — Persistent but bounded umbrella SSO creates independently revocable app/device authority, with atomic refresh rotation, scoped ordinary logout, explicit device/global controls, reliable back-channel logout, and honest outage behavior.
- [Design Workload Identity and delegated access](issues/09-design-workload-identity-and-delegation.md) — Manifest-governed workload principals receive narrow own-behalf tokens; registered one-hop exchanges preserve both human subject and workload actor, while asynchronous work uses product commands rather than stored user tokens.
- [Design identity lifecycle, privacy, and administration](issues/10-design-lifecycle-privacy-and-administration.md) — App departure remains app-scoped, global deletion uses immediate revocation plus a 30-day reversible period, products retain their own lawful evidence, and manual recovery remains disabled until true dual approval exists.
- [Design persistence, cryptography, and transactional messaging](issues/11-design-persistence-cryptography-and-messaging.md) — IAM-owned PostgreSQL uses encrypted identifier values plus keyed blind indexes, protected secret digests, constrained aggregate transactions, and broker-independent outbox/inbox delivery with idempotency and reconciliation.
- [Define APIs, events, and first-party app integration](issues/12-define-apis-events-and-app-integration.md) — Language-neutral standards and versioned APIs/events onboard each app through its private App Subject; Dutch UMS is Dutch-owned, profile readiness is app-scoped, and no global identity ID or PII enters product contracts.
- [Design operations, resilience, abuse controls, and key management](issues/13-design-operations-resilience-and-key-management.md) — Provider-neutral SLO, isolation, recovery, key custody, abuse, telemetry, incident, capacity, and cost requirements are fixed; concrete cloud products/topology remain an explicit reconciliation dependency on the separate cloud-solutions session.
- [Define verification and production acceptance](issues/14-define-verification-and-production-acceptance.md) — Risk-based TDD, protocol/database/contract/privacy/adversarial suites, failure and recovery drills, key rotation, load evidence, and an independent security gate define capability and production acceptance.
- [Define the implementation handoff and build sequence](issues/15-define-implementation-handoff.md) — Shared IAM moves to the dedicated IAM repository and is built through contract-first vertical TDD slices, with Dutch as the first app integration and explicit ownership, migration, release, and deferral boundaries.

## Not yet specified

- Exact administrative/support workflows may split into separate privacy and operations decisions once lifecycle authority is defined.
- Concrete cloud provider, region, managed service topology, IAM database physical isolation, and recurring cost remain pending reconciliation with the separately owned cloud-solutions design; ticket 13 defines the acceptance constraints.

## Out of scope

- Third-party OAuth applications and public developer onboarding.
- Customer-created tenants or customer-managed identity realms.
- Dynamic client registration by untrusted callers.
- Product profiles, preferences, balances, memberships, roles, and domain authorization.
- Generic human impersonation.
- SAML enterprise federation and social-login providers in the initial platform specification.
- Anonymous/guest identity unless a future product requirement creates a separate effort.
- Cryptocurrency wallets, government identifiers, and a runtime provider-plugin marketplace.
- Legacy production-identity migration; no application identity population is live.
