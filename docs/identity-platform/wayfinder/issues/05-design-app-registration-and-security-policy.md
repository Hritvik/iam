Type: grilling
Status: resolved
Assignee: Codex
Parent: [Specify the shared first-party Identity Platform](../map.md)
Blocked by: 01, 02

# Design App Registration and Product Security Policy

## Question

How do reviewed manifests, client profiles, resource audiences, scopes, exact redirects, activation prerequisites, ownership, environment promotion, policy minimums, and controlled reconciliation register a new first-party application without configuration drift or unsafe production mutation?

## Answer

### Registration model

The authoritative unit is an App Registration containing app metadata/ownership, App Activation policy, Product Security Policy, Client Registrations, and Resource Registrations. A client is not an app: one app may own separate iOS, Android, web BFF, confidential server, and workload clients plus multiple independently protected APIs.

Authoritative manifests live in a central, version-controlled Identity Platform registry organized by app and environment. App teams propose changes; ownership rules require the app owner and Identity Platform/security reviewers according to risk. Approved manifests reconcile into IAM's durable runtime registry. Authorization and token paths depend only on that local registry, not on Git or CI availability, while retaining source revision and canonical hash provenance.

Every manifest has a stable App Registration ID, explicit schema version, monotonic revision, environment target, canonical content hash, operational owner, and incident contact. Additive evolution is preferred; incompatible meanings use a new schema version and controlled migration. Development, staging, and production have separate issuers, client IDs, credentials, redirects, audiences, registrations, identities, sessions, and tokens. Promotion carries reviewed intent through environment-specific overlays, never secret material or runtime identity state.

### Constrained profiles and resources

Each client declares exactly one supported profile:

- `NATIVE_PUBLIC` — authorization code, exact redirect, external browser, S256 PKCE, and no client secret.
- `SERVER_WEB_CONFIDENTIAL` — authorization code plus S256 PKCE and server-held asymmetric client authentication.
- `BFF_CONFIDENTIAL` — authorization code plus S256 PKCE, hardened browser session cookie, and OAuth credentials retained only by the BFF.
- `WORKLOAD_CONFIDENTIAL` — Workload Identity authenticated by mTLS, `private_key_jwt`, or approved platform attestation, with no human session.
- `DELEGATING_WORKLOAD` — a separately approved workload limited to named token-exchange workflows.

Direct-token SPA, implicit, password, arbitrary grant combinations, and unrestricted token exchange remain prohibited.

Each independently authorized API has a stable resource/audience identifier. Access tokens target one audience by default; portfolio-wide and multi-resource tokens require a concrete reviewed exception. Resource owners define globally qualified, purpose/action scopes. Scopes express coarse API authority, never product roles, memberships, balances, subscriptions, or row-level access.

Redirect and post-logout URIs use exact environment-specific registration with no wildcards, prefixes, runtime domains, or open redirectors. Only standards-defined native loopback variable ports are exceptional. Mobile claimed HTTPS links are preferred; private-use schemes require collision review.

Manifests contain public keys/certificates, algorithms, credential references, owners, and rotation policy—never private keys or secrets. Production confidential clients prefer `private_key_jwt`, mTLS, or workload attestation. Shared secrets require a bounded reviewed exception.

### Security policy and activation

Effective security policy is the strictest combination of platform baseline, client-profile baseline, resource/API baseline, app strengthening, and operation-specific step-up. Apps may strengthen assurance, recent-authentication, factor, session, sender-constraint, or logout controls but cannot weaken inherited minimums.

IAM owns App Activation state and a typed prerequisite contract; apps or approved policy services own domain evaluation. Initial prerequisite result types cover terms/version acceptance, invitation reference, age/region eligibility, and administrator approval. IAM accepts only signed or mutually authenticated assertions from a registered policy authority, bound to App Subject, app, prerequisite type/version, outcome, issue/expiry time, and nonce/correlation context. It retains only the minimum PII-free result/version and never trusts browser/mobile self-assertion.

Pre-approved ordinary first-party scopes may avoid repetitive OAuth consent, but first activation identifies the app and umbrella Identity. Sensitive cross-app visibility, delegation, or unusually broad authority receives explicit purpose disclosure and, where appropriate, user confirmation. Claims use platform-owned allowlisted profiles. PII-bearing UserInfo contracts require separate purpose, field allowlist, retention, security approval, and negative tests.

### Governance and lifecycle

Changes use risk-tiered review: metadata-only changes need app-owner review; redirects, scopes, claims, logout, assurance, sessions, or activation policy also need Identity Platform review; new credential methods, delegation, sender constraints, privileged scopes, or production issuer/resource changes require security approval. Emergency disablement is available to bounded incident roles with retrospective review.

Promotion runs schema/policy validation, development protocol and negative tests, staging integration/security evidence, and then production reconciliation. Production is never the first exercised environment.

Drift is continuously detected. Safe missing/additive state may reconcile automatically; destructive or security-sensitive drift blocks promotion and alerts. Manual production edits are reverted or imported only through audited break-glass review, never silently adopted.

Emergency controls independently disable a credential, client, redirect, scope grant, resource, App Registration, delegation workflow, app sessions, or new issuance. Every action records reason, actor, time, correlation, bounded authority, and retrospective review. Decommissioning follows `ACTIVE → DEPRECATED → DISABLED → RETIRED`; stable IDs are never reused and audit/lifecycle references remain.

Asymmetric credentials rotate through overlapping generations with explicit activation/retirement timestamps, rehearsed before expiry and reversible until final retirement.
