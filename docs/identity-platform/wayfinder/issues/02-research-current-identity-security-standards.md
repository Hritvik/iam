Type: research
Status: resolved
Assignee: Codex/identity_standards_research
Parent: [Specify the shared first-party Identity Platform](../map.md)

# Research current identity and OAuth security standards

## Question

What do current primary standards require or recommend for native, confidential web, BFF/browser, workload, OAuth/OIDC, PKCE, token audience, sender constraint, passkey, session, logout, delegation, and authorization-server security relevant to this platform?

## Answer

The primary-source baseline is captured in [Identity Platform Security Standards Research](../../research/identity-platform-security-standards.md). OAuth 2.0 plus OpenID Connect remains the stable base, governed by the newer security BCPs rather than bare RFC 6749. The platform must use authorization code, exact redirect matching, S256 PKCE for public clients and preferably confidential clients, resource/audience binding, typed tokens, strong issuer validation, and refresh rotation or sender constraint for public clients. New implicit and resource-owner-password clients are prohibited.

Native apps use external user agents; browser apps default to a BFF; confidential clients prefer asymmetric authentication; workloads use non-human principals; and token exchange is limited to explicit delegation that preserves both subject and actor. Passkeys are WebAuthn Authentication Factors, with WebAuthn Level 2 as the stable initial baseline. Resource services locally validate issuer, signature, time, audience, subject type, client, scopes, token type, and sender constraint where present. RFC 10017 is the current browser-app BCP, while OAuth 2.1 remains a consolidation draft and is not the normative production citation.
