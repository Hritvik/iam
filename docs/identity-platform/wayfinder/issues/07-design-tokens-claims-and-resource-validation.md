Type: grilling
Status: resolved
Assignee: Codex
Parent: [Specify the shared first-party Identity Platform](../map.md)
Blocked by: 01, 02, 05, 06

# Design tokens, claims, and resource validation

## Question

What exact access, ID, authorization-code, and refresh-token profiles; claims; subject typing; audience rules; lifetimes; signing/encryption; key discovery; sender constraints; and local validation rules prevent cross-app, cross-token, and human/workload confusion?

## Decision

### Token and artifact profiles

- **Authorization codes** are opaque, high-entropy, short-lived, single-use artifacts bound to issuer, client, exact redirect URI, Human Identity, App Activation transaction, requested resource/scopes, PKCE challenge, nonce where applicable, and authenticated session. Store only a protected digest and transactional consumption state.
- **Human access tokens** are signed JWT access tokens conforming to RFC 9068. They are bearer tokens only for confidential server/BFF clients whose storage boundary is server-side; native production clients use DPoP sender-constrained access tokens.
- **Workload access tokens** use a distinct subject profile and are issued only after authenticated client-credentials or an explicitly approved exchange. High-trust workload paths use mTLS-bound tokens where the deployment preserves certificate binding; otherwise use asymmetric client authentication and narrowly scoped JWT access tokens.
- **Delegated access tokens** are a distinct short-lived profile carrying both the Human Identity-derived app subject and the workload actor. They never erase the actor, never represent generic impersonation, and never receive refresh tokens.
- **ID tokens** are signed OIDC authentication assertions for the exact client audience. Resource servers must reject them as API credentials.
- **Refresh tokens** are opaque, high-entropy credentials usable only at IAM. Store protected digests rather than recoverable token values. Bind each family to Human Identity, app, client, device/session context, authorization grant, and sender key where applicable.
- **Authorization codes, refresh tokens, OTPs, recovery codes, session handles, and administrative grants** must not be JWTs merely for convenience. Their authoritative state and one-time/revocation semantics remain durable and server-side.

### Subjects and privacy

- Ordinary human tokens use a stable pairwise **App Subject** derived for the issuer, Human Identity, and application boundary. Clients within the same reviewed application may share the App Subject; cross-application correlation requires an explicitly approved umbrella capability.
- The internal Human Identity identifier is never a normal token claim and is never returned to product applications.
- Workload tokens use a separately namespaced Workload Identity subject. Validators must reject a human subject where a workload is required and vice versa.
- Delegated tokens carry the app-scoped human subject in `sub` and the authenticated workload actor in a structured `act` claim. Policy evaluates both.
- Tokens contain no email, phone number, credential, profile field, balance, membership, product role, or other product-domain data.

### Required access-token claims

Every access token includes and validators require:

- `iss`, equal to the environment's exact configured issuer;
- `sub`, interpreted only together with the token profile and subject-kind claim;
- a single `aud` resource identifier by default;
- `exp`, `iat`, and a bounded `nbf` where used;
- `jti`, unique and non-PII;
- `client_id`;
- a registered token/profile version and explicit subject kind;
- granted `scope` values owned by the target resource;
- application identifier where the call is human/app-bound;
- authentication context (`acr`, `amr`, `auth_time`) only where resource policy requires it;
- the current identity security version for human authority; and
- `cnf` when sender constrained.

Delegated profiles additionally require the workload actor and registered delegation purpose. Claims and names are finalized in the versioned contract, not invented independently by services.

### Audience, resource, and authority

- A token has one protected-resource audience by default. IAM rejects undeclared or unauthorized `resource` targets and does not issue portfolio-wide API tokens.
- Scopes express coarse resource authority. Product roles and record-level authorization remain with the resource service.
- A client registration, resource registration, activation state, Product Security Policy, grant, and requested operation must all permit issuance. The strictest applicable rule wins.
- Tokens are never forwarded to a different audience. A service that needs another service must obtain its own workload token or use an approved delegation exchange.

### Lifetimes and refresh behavior

- Default access-token lifetime is five minutes. Delegated tokens and sensitive-operation tokens may be shorter; a longer lifetime requires a reviewed resource policy and documented outage/security rationale.
- Authorization codes expire within minutes and become unusable immediately after the first redemption attempt that reaches authoritative validation.
- Refresh tokens rotate on every successful use. Reuse of any consumed token revokes the entire family, terminates the associated app/device authority, emits a PII-free security event, and requires fresh authentication.
- Absolute and inactivity limits apply to refresh families. Their exact durations are policy values by client/risk tier and cannot exceed platform maximums.
- Recovery, global lock, identity disablement, factor compromise, app departure, client disablement, or applicable security-version advance invalidates affected refresh families immediately.

### Signing, encryption, and discovery

- Use asymmetric signing algorithms supported by current platform security policy. Do not use unsigned tokens, symmetric shared issuer signing keys, algorithm fallback, or client-selected algorithms.
- Publish issuer metadata and JWKS over HTTPS. Pin the expected issuer in every client and resource configuration; discovery does not authorize an arbitrary issuer.
- Signing keys have unique `kid` values, explicit lifecycle state, overlap during rotation, and remain published long enough to validate every unexpired token they signed.
- JWT access and ID tokens are signed, not encrypted by default. PII is prohibited rather than hidden with token encryption. Encryption requires a separately reviewed confidentiality use case and key-distribution design.
- Private signing material is obtained through the approved key-management interface and is never stored in source, manifests, database migrations, logs, or test fixtures intended for production.

### Sender constraints

- DPoP is mandatory from the first production registration of native clients and sender-constrains both access and refresh tokens. IAM and resources validate proof signature, public-key thumbprint, method, URI, issuance time, unique proof ID, access-token hash where applicable, and nonce/replay policy.
- Device key loss creates a new device session and refresh family after authentication; sender binding is never silently transferred.
- Confidential workload clients use `private_key_jwt` by default. mTLS authentication and certificate-bound tokens are required for risk tiers whose network and certificate infrastructure preserve end-to-end binding.
- BFF/browser sessions keep tokens server-side. DPoP is not mandatory for the browser cookie; the BFF's server-side OAuth client follows its confidential-client policy.

### Resource validation and revocation projection

Resource servers must use a shared, versioned validation library or conformance suite while retaining local authorization ownership. Before accepting a token they validate:

1. syntactic limits and expected `typ` (`at+jwt`);
2. exact issuer and allowed signing algorithm;
3. signature against a trusted cached JWKS key;
4. `exp`, `nbf`, `iat`, and bounded clock skew;
5. exact audience/resource;
6. registered token/profile version and expected subject kind;
7. client/application relationship and scopes;
8. sender constraint where present or required;
9. authentication assurance/recentness required by the operation; and
10. the token's identity security version against the resource's local projection.

IAM emits a PII-free, monotonic identity-security-version event for global lock, account recovery, identity disablement, and comparable global compromise actions. Resources project the latest version keyed by their App Subject and reject older tokens. This gives near-real-time compromise response without live introspection and preserves local validation during a temporary IAM outage.

Ordinary app logout revokes the app/session refresh family and application session; it does not advance the portfolio-wide security version. Already issued access tokens may remain usable until their short expiry unless a more specific app-local revocation projection is justified by that resource's risk policy.

If the security-version projection is unavailable or stale, the resource follows its declared risk-tier outage policy. It must never call IAM synchronously as an undocumented fallback.

### Prohibitions

- No access or refresh token in URLs, logs, events, analytics, crash reports, or API response envelopes other than the standards-defined token endpoint response to the authenticated client.
- No acceptance of ID tokens, authorization codes, refresh tokens, DPoP proofs, or tokens for another audience as API access tokens.
- No `alg: none`, algorithm confusion, unbounded JWKS fetching, issuer discovery from an incoming token, or permissive claim parsing.
- No raw token persistence. Test fixtures use non-production deterministic keys and tokens under explicit test configuration only.
