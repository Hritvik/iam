Type: grilling
Status: resolved
Assignee: Codex
Parent: [Specify the shared first-party Identity Platform](../map.md)
Blocked by: 01, 02, 05, 06, 07

# Design Workload Identity and delegated access

## Question

How are workload principals provisioned, authenticated, rotated, scoped, and audited; which named workflows may carry Delegated Access; and how are human subject, workload actor, audience, purpose, lifetime, and non-impersonation enforced?

## Decision

### Workload Identity model

- A Workload Identity represents one deployed software workload or narrowly defined automation boundary. It is never a synthetic Human Identity, never owns a Verified Identifier or passkey, and cannot create a Platform SSO Session.
- Workload Identity, OAuth Client Registration, deployment instance, and application are separate concepts. A stable Workload Identity may have environment-specific client credentials and multiple rotating credential generations, while a broad application may own several workloads with different blast radii.
- Every workload has a stable non-reused identifier, owning App Registration, environment, owner and incident contact, purpose, risk tier, allowed client profile, resource audiences, scopes, credential policy, network/deployment constraints, lifecycle state, and review/expiry metadata.
- Production workloads are provisioned only through the reviewed App Registration manifest and reconciliation path. Runtime self-registration and shared portfolio-wide service accounts are prohibited.

### Authentication and credentials

- Prefer platform-native workload attestation/federation when the eventual deployment substrate provides a verifiable short-lived identity assertion. The IAM integration must validate exact issuer, audience, subject, deployment/environment attributes, and replay limits; mere possession of cloud metadata is insufficient.
- `private_key_jwt` is the portable default for confidential workloads. Each workload controls its private key through the approved secret/key service; IAM stores only public verification material and credential metadata.
- Require mTLS client authentication and certificate-bound access tokens for risk tiers where certificate identity remains available end to end and lifecycle automation is proven.
- Shared client secrets are development-only by default. A production exception requires risk approval, secret-manager storage, short rotation, non-exportability where available, and a migration plan.
- Credential generations overlap during rotation. Compromise can disable one credential without deleting the Workload Identity. Private keys, assertions, certificates containing private material, and access tokens never enter manifests, events, audit payloads, or logs.

### Own-behalf workload authority

- Client credentials issue a token only for the workload acting on its own behalf. The token has a Workload Identity subject kind, one audience, resource-owned scopes, short lifetime, no Human Identity/App Subject, no `act` claim, and no refresh token.
- Each resource explicitly admits permitted workload subjects/scopes. Being an internal or first-party service conveys no ambient authority.
- Workload tokens cannot be exchanged into human authority, cannot call human-only endpoints, and cannot satisfy app activation or recent-authentication requirements.

### Delegated Access model

Token exchange is available only to a `DELEGATING_WORKLOAD` for a named, versioned Delegation Workflow registered in the manifest. The default is no delegation workflows. Enabling the protocol endpoint does not authorize an exchange.

A workflow declares:

- initiating app/client and permitted authenticated human token profile;
- exact actor Workload Identity or bounded actor set;
- source and target audience;
- permitted scope transformation, always equal or narrower;
- business purpose code and user-facing disclosure requirement;
- minimum authentication assurance and maximum authentication age;
- activation/session/security-version prerequisites;
- maximum delegated-token lifetime;
- whether only synchronous use is allowed;
- resource-side authorization obligations;
- audit/event classification, owner, expiry/review date, and emergency disable control.

The exchange validates the source token, DPoP/sender binding where applicable, current security version, actor authentication, exact workflow, resource, requested scope, assurance, activation, and purpose. The issued token:

- uses the target resource as its sole audience;
- carries the app-scoped human subject as `sub`;
- carries the authenticated workload in structured `act` semantics;
- identifies the registered delegation workflow and purpose;
- has narrow scopes and a short lifetime no longer than the source authority;
- is sender constrained when workflow policy requires it;
- cannot be refreshed or recursively exchanged unless a separately registered bounded chain explicitly permits one additional hop; and
- never carries a global Human Identity ID or PII.

Resource authorization evaluates human subject, workload actor, purpose, app/activation context, scope, and domain policy. A delegated token is never treated as if the human called directly.

### Permitted patterns

- A synchronous app API may exchange a valid human token for a narrower token to call one downstream resource when that resource needs both the app-scoped human subject and the calling service actor.
- A controlled orchestration service may obtain one-hop delegated authority for a named user-requested operation, such as generating an export from data already authorized by the owning product.
- A sensitive command may require recent Strong authentication before IAM permits the workflow exchange.

### Prohibited patterns

- Generic “act as”, “login as”, support impersonation, actor omission, portfolio-wide delegation, wildcard audiences/scopes, or exchange based solely on a caller-supplied Human Identity/App Subject.
- Passing an end-user access token through multiple services or forwarding it to a different audience.
- Putting access or refresh tokens on queues, event buses, job payloads, logs, URLs, or durable workflow records.
- Issuing long-lived delegated tokens or refresh tokens to background jobs.
- Treating token exchange as product authorization or ownership transfer.

Asynchronous work records a product-owned, immutable command/authorization snapshot at acceptance time and later runs under the worker's own Workload Identity. The product decides whether execution must re-check current domain authority. If fresh human authorization is required, execution pauses and requests a new user interaction; it does not preserve a user token.

### Audit and lifecycle

- Successful and denied workload authentication and exchange record PII-free actor, workflow, audience, scopes, purpose, credential generation, result/reason, correlation, causation, and time. Raw assertions, tokens, App Subject values beyond the resource's approved correlation boundary, and request payloads are excluded.
- Workload and workflow states are `ACTIVE`, `SUSPENDED`, `DEPRECATED`, `DISABLED`, and `RETIRED`. Stable identifiers are not reused.
- Emergency controls independently disable a credential, Workload Identity, delegation workflow, target audience, or issuance path. Existing short-lived tokens follow resource projection and expiry policy.
- Owners periodically attest that each workload/workflow remains necessary. Expired attestations block new credential issuance or delegation according to risk policy rather than silently extending privilege.
