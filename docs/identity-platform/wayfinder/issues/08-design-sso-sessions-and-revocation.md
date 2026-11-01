Type: grilling
Status: resolved
Assignee: Codex
Parent: [Specify the shared first-party Identity Platform](../map.md)
Blocked by: 04, 06, 07

# Design SSO, sessions, refresh families, and revocation

## Question

How do Platform SSO Sessions and app/device-bound sessions implement seamless entry, recent-authentication policy, refresh rotation, replay response, device/app/global logout, compromise locks, concurrent use, and honest outage behavior?

## Decision

### Session hierarchy

IAM models related but independently controllable authority at four levels:

1. **Platform SSO Session** — an authenticated IAM browser or system context for one Human Identity on one device context. It enables seamless authorization across first-party apps but grants no product API authority itself.
2. **App Session** — the application's own local session, bound to one App Subject, application, client, and device context. IAM does not store product-session payloads, and the application does not store IAM credentials in browser-readable storage.
3. **Refresh Family** — durable renewable OAuth authority for one identity, app, client, device, authorization grant, and sender key where applicable. An app/device may have more than one family only when separate approved clients or grants require it.
4. **Access Token** — short-lived, single-resource authority whose validity follows the token profile and local security-version projection.

An existing Platform SSO Session can satisfy a new application's authorization request only after exact client/redirect/resource validation, App Registration and policy evaluation, prerequisite checks, and idempotent App Activation. SSO never bypasses activation policy, consent/disclosure requirements, step-up, or app-specific session creation.

### Persistence and assurance

- Personal-device Platform SSO Sessions default to a maximum 30-day inactivity period and 90-day absolute lifetime. These are configurable platform maxima and may be shortened by environment, risk tier, client profile, device posture, recovery state, or user choice.
- Shared, untrusted, recovered, or high-risk contexts receive session-only or shorter persistence. No client can request a longer session than platform policy permits.
- A session records the assurance achieved, methods, authentication time, factor references, recovery restriction, risk reasons, device-session reference, creation/last-use times, and absolute/inactivity expiry without storing raw device fingerprints in tokens or events.
- Reusing SSO does not refresh `auth_time`. Operations requiring recent or stronger authentication cause an explicit IAM step-up. Successful step-up creates bounded recent-auth evidence for the requesting app/operation and may strengthen the Platform SSO Session only as policy explicitly permits.
- Recovery creates a restricted Baseline session and never inherits the assurance or recent-auth state of revoked sessions.

### Concurrent use and session management

- Multiple devices and concurrent sessions are permitted by default. Do not impose a small arbitrary device limit that encourages unsafe sharing or creates account lockout.
- Deterministic anomaly and compromise rules may challenge, restrict, or revoke a particular device/session. Portfolio-wide lock requires credible global compromise or governed operator action.
- IAM provides a minimal user-facing security surface showing recognizable device/session labels, approximate recent activity, participating applications, assurance/recovery restrictions, and revocation controls. It must not reveal one app's product activity to another app.
- Device labels are user-facing hints, not trusted identifiers. Device/session metadata is minimized, retained under policy, and never used as a substitute for authentication.

### Refresh rotation and replay

- Every refresh use atomically validates the current family/member, sender binding, client, grant, expiry, activation, and security version; consumes the presented member; creates exactly one successor; and records the audit/outbox effects in one transaction.
- Concurrent redemption of the same member has one winner. A later presentation is reuse, not an idempotent retry, except for a narrowly bounded server-side response-recovery mechanism that returns no reusable token value from storage.
- Confirmed reuse revokes the entire affected refresh family, ends the corresponding app/device authority, records a reason-coded security incident, and emits a PII-free event. It does not automatically lock unrelated devices unless risk policy identifies broader compromise.
- Refresh responses and token values never enter logs, events, analytics, traces, crash reports, or durable plaintext storage.

### Logout and revocation scopes

Ordinary **Log out** means the current application on the current device. It terminates the app's local session and corresponding refresh family, clears client cookies/tokens, and initiates applicable OIDC logout coordination. It does not unexpectedly terminate every umbrella application.

IAM additionally supports explicit commands with clear confirmation:

- **Log out of this app on this device** — current app session and refresh family.
- **Log out of this app on all devices** — every refresh family and server-side app session for the App Activation.
- **Log out of all apps on this device** — Platform SSO Session and all app families linked to that device-session context.
- **Log out everywhere** — every Platform SSO Session and refresh family for the Human Identity; advances the global security version when immediate access-token invalidation is required by policy.
- **Leave app** — ends authority and transitions the App Activation according to lifecycle policy; it is distinct from logout and product-data deletion.
- **Security lock/recovery/identity disablement** — global authoritative revocation, security-version advancement, and the restrictions defined by the triggering lifecycle.

Revocation commands are idempotent and return the same safe outcome when the target is already terminated. Audit records preserve who/what initiated the action, scope, reason class, correlation, and outcome without tokens or PII.

### Logout propagation

- Confidential server-web and BFF clients register authenticated OIDC back-channel logout endpoints. IAM sends signed logout tokens with exact issuer/audience/event validation requirements and stable session references; clients process duplicates idempotently.
- RP-Initiated Logout is the user-facing entrypoint. Front-channel notification may improve UX but is never the only enforcement mechanism.
- Native clients clear local credentials and app state after their logout command. Refresh revocation, DPoP binding, short access-token expiry, and security-version projection provide server-side enforcement; IAM cannot assume delivery of a push/logout callback.
- A failed back-channel delivery is retried durably and exposed operationally. It does not roll back the authoritative IAM revocation.

### Outage behavior

- Resource APIs may continue accepting unexpired access tokens only when signature, issuer, audience, type, scope, sender binding, assurance, and the locally projected security version validate.
- Existing application sessions may continue within their own local risk policy without calling IAM merely to prove liveness.
- Authorization, login, SSO reuse that creates new authority, refresh, logout confirmation, first activation, recovery, factor/identifier changes, session listing, and authoritative revocation require IAM. They fail closed or report a retryable dependency failure when IAM is unavailable.
- Applications never claim that a global logout completed until IAM accepted it. They may always clear their own local session immediately and report that umbrella revocation is pending or unavailable.
- Cached JWKS and security projections have explicit freshness/overlap policy. A resource at a risk tier whose projection is too stale follows its declared fail-open-until-expiry or fail-closed policy; no hidden synchronous introspection fallback is allowed.
