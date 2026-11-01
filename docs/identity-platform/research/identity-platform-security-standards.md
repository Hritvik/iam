# Identity Platform Security Standards Research

Status as of 2026-08-23. Sources are primary standards or official standards-body pages only.

## Executive summary

The platform should treat OAuth 2.0 plus OpenID Connect as the stable production baseline, with OAuth 2.1 used only as a consolidation draft until it becomes an RFC. The current mandatory security posture is closer to RFC 9700 and RFC 10017 than bare RFC 6749: authorization code, exact redirect matching, PKCE for public clients, PKCE recommended for confidential clients, no implicit flow for new clients, no resource-owner-password flow, refresh-token rotation or sender constraint for public clients, and issuer/audience/resource binding everywhere.

The recommended first-party portfolio remains:

- Native public apps: authorization code with S256 PKCE through the external browser, exact registered redirects, no embedded webviews, app/device-bound refresh families, and refresh rotation or sender constraint.
- Confidential server web apps: authorization code with client authentication, PKCE, state/nonce binding, exact redirects, server-side token storage, and OIDC session/logout integration.
- Browser apps: prefer a Backend-for-Frontend where the browser holds only an application session cookie; direct browser OAuth clients are an exception and must use authorization code with PKCE, strict XSS controls, careful refresh-token handling, and preferably DPoP.
- Workloads: use workload principals, not synthetic humans. Client credentials are for own-behalf access; private_key_jwt or mTLS are the preferred production client authentication methods; token exchange may represent delegation, but generic impersonation should stay prohibited.

## Standards status

| Area | Primary source | Status | Practical use |
| --- | --- | --- | --- |
| OAuth 2.0 core | [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html) | Standards Track, Oct 2012 | Base model only; apply later BCPs and extensions. |
| Bearer tokens | [RFC 6750](https://www.rfc-editor.org/info/rfc6750/) | Standards Track, Oct 2012; updated by RFC 9700 | Use only over TLS; avoid URI query token transport. |
| OAuth security BCP | [RFC 9700 / BCP 240](https://www.rfc-editor.org/info/rfc9700/) | Best Current Practice, Jan 2025 | Governing security baseline. |
| Native apps | [RFC 8252 / BCP 212](https://www.rfc-editor.org/info/rfc8252/) | Best Current Practice, Oct 2017 | Governing native/mobile profile. |
| Browser apps | [RFC 10017 / BCP 212](https://www.rfc-editor.org/info/rfc10017/) | Best Current Practice, 2026 | Governing browser/SPA/BFF profile. |
| PKCE | [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html) | Standards Track, Sep 2015 | Use S256. |
| Resource indicators | [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) | Standards Track, Feb 2020 | Let clients request tokens for explicit protected resources. |
| Protected resource metadata | [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html) | Standards Track, 2025 | Let resources advertise issuer/scopes/bearer methods. |
| JWT access-token profile | [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html) | Standards Track, Oct 2021 | If access tokens are JWTs, follow this profile. |
| mTLS sender constraint | [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705) | Standards Track, Feb 2020 | Strong fit for workloads and service-to-service paths. |
| DPoP sender constraint | [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html) | Standards Track, Sep 2023 | Strong fit for native and browser public clients when mTLS is not practical. |
| Token revocation | [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html) | Standards Track, Aug 2013 | Required for logout and compromise response. |
| Token exchange | [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html) | Standards Track, Jan 2020 | Use only with explicit local policy for delegation. |
| JWT client auth | [RFC 7523](https://www.rfc-editor.org/info/rfc7523/) | Standards Track, May 2015 | Basis for private_key_jwt and JWT bearer assertions. |
| AS metadata | [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html) | Standards Track, Jun 2018 | Publish issuer and supported endpoints/capabilities. |
| OIDC Core | [OpenID Connect Core 1.0 errata set 2](https://openid.net/specs/openid-connect-core-1_0.html) | OpenID Foundation Final, Dec 2023 errata | Human authentication and ID token model. |
| OIDC Discovery | [OpenID Connect Discovery 1.0 errata set 2](https://openid.net/specs/openid-connect-discovery-1_0.html) | OpenID Foundation Final, Dec 2023 errata | OP metadata and endpoint discovery. |
| OIDC RP logout | [OIDC RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) | OpenID Foundation Final, Sep 2022 | User-initiated SSO logout entrypoint. |
| OIDC back-channel logout | [OIDC Back-Channel Logout 1.0 errata set 1](https://openid.net/specs/openid-connect-backchannel-1_0.html) | OpenID Foundation Final, Dec 2023 errata | More reliable server-to-server RP logout. |
| Step-up challenge | [RFC 9470](https://www.rfc-editor.org/rfc/rfc9470.html) | Standards Track, Oct 2023 | Resource-driven assurance/recent-auth challenges. |
| WebAuthn passkey substrate | [WebAuthn Level 2](https://www.w3.org/TR/webauthn-2/) | W3C Recommendation, Apr 2021 | Stable production WebAuthn baseline. |
| WebAuthn Level 3 | [W3C WebAuthn Level 3 history](https://www.w3.org/standards/history/webauthn-3/) and [2026 charter](https://www.w3.org/2026/08/wg-webauthn-charter.html) | Candidate Recommendation Snapshot, May 2026; undergoing Recommendation review | Useful but do not require Level 3-only features for MVP. |
| FIDO/passkeys | [FIDO specifications overview](https://fidoalliance.org/specifications/) and [FIDO passkeys](https://fidoalliance.org/passkeys/) | FIDO standards and guidance | Treat passkeys as authentication factors, not identifiers. |
| OAuth 2.1 | [draft-ietf-oauth-v2-1-15](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/writeup/) | IETF draft awaiting RFC publication path, not a final RFC | Reference for direction only; cite RFCs/BCPs in production requirements. |

## Requirements for Dutch umbrella IAM

### 1. Authorization server and issuer

Use one issuer per environment and publish metadata. RFC 8414 defines an issuer identifier as an HTTPS URL with no query or fragment and uses it to prevent mix-up attacks; OIDC Discovery defines how RPs obtain OP endpoint metadata. The design should make issuer, JWKS, supported grant types, response types, code challenge methods, DPoP/mTLS support, revocation, introspection, and logout endpoints explicit in metadata.

Clients must bind every authorization response to the issuer they started with. RFC 9700 requires mix-up defenses when a client can interact with more than one AS and recommends issuer validation or distinct redirect URIs. Even if Dutch initially uses one umbrella issuer, store issuer per transaction so later multi-environment or admin tooling does not create an implicit assumption.

### 2. Redirects, PKCE, and authorization-code flow

Use authorization code for human clients. RFC 9700 requires public clients to use PKCE and recommends PKCE for confidential clients; it also says authorization servers must support PKCE. RFC 7636 makes S256 mandatory to implement on the server and says capable clients must use S256. Therefore every first-party app registration should declare exact redirect URIs and require S256 PKCE; `plain` should be disabled unless a reviewed legacy exception exists.

Do not add new implicit-flow or resource-owner-password clients. RFC 10017 explains that browser best practice is authorization code with PKCE, and RFC 9700 deprecates insecure modes. The original password grant in RFC 6749 required direct client access to the user's credentials; that violates the IAM boundary and must not be used for Dutch, Midas, Jarvis, or later first-party apps.

### 3. Native public clients

Native apps must use an external user-agent, primarily the browser. RFC 8252 states that native authorization requests should be made through external user-agents and that embedded user-agents must not be used because the host app can observe credentials, consent, and cookies. Redirects must match registered values exactly; RFC 8252 calls this out as required to prevent interception attacks.

For mobile, support claimed HTTPS app links/universal links where product UX allows, private-use schemes only with collision controls, and loopback only for desktop/native profiles that need it. All native clients are public clients, so no client secret may be treated as secret. Refresh tokens for public clients must be rotated or sender-constrained per RFC 9700; for this platform, model refresh families per Human Identity, app, client, and device.

### 4. Confidential web clients

Confidential server-rendered or server-owned web clients can hold client credentials and tokens on the server. RFC 6749 defines confidential clients as clients capable of keeping credentials confidential, and web applications as server-side clients whose issued tokens are stored on the web server. For these clients, use authorization code with client authentication, PKCE, state/nonce binding, exact redirects, server-side token storage, and CSRF protection.

Prefer asymmetric client authentication (`private_key_jwt` from RFC 7523) or mTLS (RFC 8705) over shared client secrets for production. Shared secrets are acceptable only for development or low-risk internal clients if secret storage, rotation, and environment separation are explicit.

### 5. Browser/BFF clients

For first-party browser experiences, prefer the BFF pattern: the browser authenticates through the backend, holds a hardened application session cookie, and never receives OAuth access or refresh tokens. RFC 10017 identifies BFF as a main browser architecture pattern and emphasizes that malicious JavaScript can take over the browser execution context. BFF does not eliminate XSS risk, but it keeps bearer/refresh tokens out of JavaScript.

If a direct browser OAuth client is later allowed, it must be treated as a public client: authorization code with S256 PKCE, no implicit flow, strict CSP and dependency integrity controls, no long-lived bearer refresh token in JavaScript-readable storage, refresh rotation or DPoP, and clear exception approval. This should not be a default client type for Dutch's umbrella platform.

### 6. Resource/audience binding

Every access token must be resource-bound. RFC 8707 defines the `resource` parameter so a client can identify the protected resource it wants to access. RFC 9068 requires JWT access tokens to include `aud`, and RFC 9728 lets protected resources publish metadata such as resource identifier, supported authorization servers, scopes, and bearer methods.

For this platform, each app/service API should have a stable audience/resource identifier. IAM should reject over-broad target requests and avoid multi-resource tokens unless a reviewed use case proves they are necessary. Resource services must validate issuer, signature/key, expiration, audience/resource, subject type, client/app, scopes, token type, and sender constraint where present.

### 7. Sender-constrained tokens

Use sender constraint where token theft risk justifies the operational cost.

DPoP is an application-layer proof-of-possession mechanism for access and refresh tokens. RFC 9449 says it lets clients prove possession of a key pair via a DPoP proof JWT and can sender-constrain refresh tokens for public clients; it is not itself client authentication. This fits native apps and exceptional browser clients, provided the implementation handles proof replay, nonce policy, key storage, and resource-server validation.

mTLS is stronger for service-to-service and workload paths where certificate lifecycle is manageable. RFC 8705 defines both mutual-TLS client authentication and certificate-bound access tokens, and notes those mechanisms are distinct but complementary. Use mTLS-bound tokens for high-trust internal workloads where ingress, service mesh, certificate rotation, and TLS termination preserve the client certificate binding end to end.

### 8. Refresh tokens, revocation, and replay

Refresh tokens are only for the authorization server and must never be sent to resource servers. RFC 6749 defines refresh tokens as credentials used to obtain access tokens and says they are intended for use only with authorization servers. RFC 9700 requires sender-constrained or rotated refresh tokens for public clients.

IAM should store refresh-token families durably, detect reuse, revoke the family on replay, and emit only PII-free security lifecycle facts. RFC 7009 defines token revocation so clients can invalidate tokens on logout, identity change, uninstall, or cleanup. App logout, device logout, app-wide revocation, global logout, compromise locks, and app departure should be separate commands with explicit blast radius.

### 9. OIDC human authentication and sessions

Use OIDC Core for human authentication, not OAuth access tokens as identity assertions. OIDC Core defines ID Tokens and authentication claims on top of OAuth; access tokens remain authorization artifacts for resource servers. Do not let resource APIs accept ID Tokens as access tokens; RFC 9068 explicitly warns about token-type confusion and requires JWT access tokens to declare `typ` as `at+jwt`.

Use OIDC Discovery and AS metadata for client configuration, but keep first-party app registration authoritative in reviewed manifests rather than dynamic registration by untrusted callers. RP-Initiated Logout provides the user-facing OP logout request. Back-channel logout is preferable for server-side clients that need more reliable RP notification, but each RP must still terminate its own local session. Treat front-channel notification as best effort.

### 10. Passkeys and authentication factors

Passkeys are authentication factors, not identifiers. W3C WebAuthn defines origin/RP-scoped public-key credentials created subject to user consent, and FIDO describes passkeys as public-key credentials bound to a service domain with privacy protections. IAM should store passkey credential public keys, counters/backup eligibility/sign-count policy as applicable, attestation policy, and factor lifecycle state without copying product profile data.

Use WebAuthn Level 2 as the stable production baseline. WebAuthn Level 3 was still a Candidate Recommendation Snapshot on 2026-05-26 and, per the W3C 2026 charter, was undergoing review for transition to Recommendation as of August 2026. Do not require Level 3-only features for the initial build; allow additive adoption later for capabilities such as related origins or PRF only after platform support and recovery implications are settled.

### 11. Workload identity and delegated access

Workload Identity must be separate from Human Identity. RFC 6749 client credentials are appropriate when the client acts on its own behalf or on a prearranged authorization. Production workload clients should authenticate with private_key_jwt or mTLS, have scoped audiences, rotate keys/certificates, and use no human refresh-token families.

Delegated Access can use RFC 8693 token exchange only for named workflows. RFC 8693 explicitly distinguishes impersonation, where the actor is indistinguishable from the subject, from delegation, where the actor remains separately represented. Dutch should prohibit generic impersonation and require delegated tokens to carry both human subject and workload actor semantics, narrow audience/scope, purpose, short lifetime, no refresh token, and audit correlation.

### 12. Step-up and product security policies

Resource services may need stronger or more recent authentication for sensitive actions. RFC 9470 defines a way for resource servers to signal insufficient authentication strength or recentness and for clients to request the AS to satisfy it. IAM should expose assurance and recent-auth claims, while each Product Security Policy can strengthen platform minimums for its own app but cannot weaken the umbrella baseline.

### 13. Privacy and PII boundary

Standards permit email/phone/userinfo claims, but Dutch's product boundary does not. IAM may own verified identifiers and OIDC identity claims internally, yet UMS, Ledger, events, logs, and API responses must receive only opaque IDs, app activation facts, assurance/factor state where necessary, and PII-free mapping events. If UserInfo is exposed at all, it must be a first-party, app-scoped contract with explicit PII review; the default should be no raw email/phone outside IAM.

## Design implications

1. App registration manifests should include issuer environment, client type, redirect URIs, allowed grants, PKCE method policy, token endpoint auth method, resource audiences, scopes, Product Security Policy, logout endpoints, sender-constraint capability, owner, and promotion gates.
2. Token profiles should distinguish ID tokens, access tokens, refresh tokens, authorization codes, DPoP proofs, workload tokens, and delegated tokens. Token type confusion should be a test category.
3. Resource services should validate locally during IAM outages only for unexpired, correctly scoped, correctly audience-bound, correctly typed tokens using cached JWKS and projected revocation/security state. Login, refresh, recovery, factor changes, global logout, and first app activation require IAM availability.
4. Direct browser OAuth clients should be an exception path; BFF is the recommended first-party web shape.
5. Passkey support should start from WebAuthn Level 2 and platform passkey UX, with Level 3 features explicitly deferred.
6. Token exchange should be modeled as a controlled delegation feature, not a general "login as user" escape hatch.

## Open questions for later tickets

- Which sender-constraint profile is mandatory per client class: DPoP for native, optional DPoP for browser exceptions, mTLS for workloads, or a phased rollout?
- Whether access tokens are always JWTs following RFC 9068 or whether high-risk APIs use opaque tokens plus introspection.
- Exact assurance taxonomy and claim names for passkey, recent-auth, recovery, and step-up state.
- Whether OP logout uses only RP-Initiated Logout plus app-local revocation at first, or includes Back-Channel Logout for all confidential clients.
- Whether protected resource metadata from RFC 9728 is required for every internal API at launch or introduced after static app manifests.

