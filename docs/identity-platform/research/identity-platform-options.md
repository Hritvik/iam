# Identity Platform options research

Date: 2026-08-23

Ticket: [`Research candidate Identity Platform approaches`](../wayfinder/issues/03-research-identity-platform-options.md)

## Scope

This note compares candidate approaches for the shared first-party Identity Platform for Dutch, Midas, Jarvis, and later umbrella applications. It separates sourced facts from implications for our requirements. It does not select a winner.

Requirements kept in view:

- One Human Identity across first-party apps, with app-specific App Activations.
- One issuer per environment, app-specific clients, audiences, scopes, redirects, refresh-token families, and Product Security Policies.
- IAM owns identifiers, factors, credentials, sessions, OAuth/OIDC, workload principals, App Registrations, App Activations, and lifecycle events.
- Apps own profiles, product data, and domain authorization.
- Raw email/phone, credentials, access tokens, refresh tokens, and other PII must not enter app services, events, logs, or API responses.
- First-party only; no public third-party developer platform in the initial design.

## Comparison snapshot

| Option | Verified fit | Main implication for this platform |
| --- | --- | --- |
| Spring Authorization Server | Framework-level OAuth/OIDC implementation on Spring Security; supports core OAuth/OIDC flows and extension points, but identity, factor, verified-identifier, lifecycle, admin, events, and operations are ours to build. | Best treated as a protocol engine embedded in a custom IAM, not as a complete IAM product. High control, high build burden. |
| Keycloak | Full IAM server with users, SSO sessions, clients, client scopes, protocol mappers, service accounts, client policies, token revocation/introspection, events/SPIs, WebAuthn/passkeys, and admin APIs. | Strongest self-hosted complete-product baseline, but its built-in user/profile model and token claim defaults must be constrained to preserve our PII boundary. |
| ZITADEL | Productized IAM with OIDC/OAuth, passkeys, service accounts, Actions, Event API, organizations/projects, and event-sourced internals. Current source license is AGPL-3.0-only unless using commercial terms. | Good productized control plane and event model; legal/commercial review matters early, and custom identity boundary must fit its model. |
| Ory stack | Hydra is an OAuth/OIDC server that delegates login/consent to external systems and does not manage users; Kratos manages identities, self-service flows, schemas, verification/recovery, MFA/WebAuthn; Ory Network adds managed operations/events. | Strong composable/hybrid candidate when we want to keep identifier vault and activation policy in our own service while outsourcing protocol mechanics. More integration glue than Keycloak/ZITADEL. |
| Managed providers: Auth0, AWS Cognito | Managed OAuth/OIDC products with client/app flows, hosted login, refresh-token rotation, M2M/client credentials, hooks/actions/triggers, pricing tied to MAU/features/token volume. | Lowest infrastructure burden, highest vendor-shape and data-residency/portability constraints. Need proof that PII, event, and app-bound-token requirements can be enforced without provider lock-in surprises. |
| Hybrid external protocol engine | Use a protocol engine such as Hydra or SAS while our IAM owns Human Identity, identifier vault, factors, App Registration policy, App Activation, events/outbox, and product integration contracts. | Most aligned with bespoke boundaries if we accept building more IAM product surface. Needs careful protocol conformance and operational ownership. |

## Spring Authorization Server

### Verified facts

- Spring Authorization Server is installed as a Spring Boot starter or library and is designed for use where Spring Security is already used. Its reference calls it a secure, lightweight, customizable foundation for OAuth 2.1 and OpenID Connect 1.0 authorization server products. Sources: [Spring SAS getting started](https://docs.spring.io/spring-authorization-server/reference/getting-started.html), [Spring Security OAuth 2.1 Authorization Server](https://docs.spring.io/spring-security/reference/servlet/oauth2/authorization-server/index.html).
- Its supported protocol surface includes authorization code, client credentials, refresh token, device authorization, token exchange, and OIDC authorization code flow. Source: [Spring Security OAuth 2.1 Authorization Server](https://docs.spring.io/spring-security/reference/servlet/oauth2/authorization-server/index.html).
- Client configuration is represented by `RegisteredClient`; it includes redirect URIs, post-logout redirect URIs, grant types, scopes, client settings such as PKCE requirement, and token settings such as access/refresh TTL and refresh-token reuse. Source: [Spring SAS core model](https://docs.spring.io/spring-authorization-server/reference/core-model-components.html).
- Core components are explicit extension points, including `RegisteredClientRepository`, `OAuth2AuthorizationService`, `OAuth2AuthorizationConsentService`, token generator/customizer paths, and JWK/JWT configuration. Sources: [Spring SAS core model](https://docs.spring.io/spring-authorization-server/reference/core-model-components.html), [Spring SAS configuration model](https://docs.spring.io/spring-authorization-server/reference/configuration-model.html).
- Spring provides a JPA how-to for implementing SAS core services, and the guide frames it as a starting point intended for modification. Source: [Spring SAS JPA guide](https://docs.spring.io/spring-authorization-server/reference/guides/how-to-jpa.html).
- OIDC dynamic client registration exists but is disabled by default in the default OIDC endpoint configuration. Source: [Spring SAS configuration model](https://docs.spring.io/spring-authorization-server/reference/configuration-model.html).

### Inference for our requirements

- SAS gives strong control over database schema, outbox, identifier vaulting, app-registration reconciliation, event emission, and Product Security Policy because those product capabilities are not pre-owned by the framework.
- SAS does not remove the need to design and implement identity verification, passkeys/factors, account recovery, support/admin tooling, session UX, device inventory, abuse controls, lifecycle events, migration tooling, and production operations.
- If selected, it should be evaluated as "build custom IAM on Spring/Spring Security" rather than "adopt IAM product." That is attractive for exact PII and app-boundary control, but high-risk for schedule and security unless backed by strict conformance/security testing.

## Keycloak

### Verified facts

- Keycloak is an open-source identity and access management server; its docs describe applications and services pointing to a separate Keycloak server for authentication and authorization, using OIDC and SAML. Sources: [Keycloak homepage](https://www.keycloak.org/), [Keycloak server administration guide](https://www.keycloak.org/docs/latest/server_admin/index.html).
- Keycloak has realms, clients, client scopes, protocol mappers, role scope mappings, users, sessions, identity providers, user federation, required actions, service accounts, and admin-visible sessions. Source: [Keycloak server administration guide](https://www.keycloak.org/docs/latest/server_admin/index.html).
- OIDC clients can use built-in service accounts to obtain access tokens using the client credentials grant. The guide states only an access token is returned by default, no refresh token is returned, and no user session is created by default for service-account authentication. Source: [Keycloak server administration guide](https://www.keycloak.org/docs/latest/server_admin/index.html).
- Keycloak supports client scopes and protocol mappers that control claims in tokens. It also documents lightweight access tokens intended to remove PII from access tokens and use introspection for fuller data. Source: [Keycloak server administration guide](https://www.keycloak.org/docs/latest/server_admin/index.html).
- Keycloak documents client policies/conditions/executors for enforcing client behavior, including PKCE-related and OAuth/FAPI-style controls, and supports dynamic client registration and admin REST configuration. Source: [Keycloak server administration guide](https://www.keycloak.org/docs/latest/server_admin/index.html).
- Keycloak supports token revocation patterns, including pushing a not-before policy to invalidate tokens issued before a time, and recommends PKCE to defend against leaked authorization codes. Source: [Keycloak server administration guide](https://www.keycloak.org/docs/latest/server_admin/index.html).
- Keycloak exposes an Admin REST API and the project repository is Apache-2.0 licensed. Sources: [Keycloak Admin REST API](https://www.keycloak.org/docs-api/latest/rest-api/index.html), [Keycloak repository](https://github.com/keycloak/keycloak).

### Inference for our requirements

- Keycloak is the most complete self-hosted IAM product in this set, especially for client administration, SSO sessions, service accounts, mappers, policies, admin API, and operational familiarity.
- The risk is boundary inversion: Keycloak wants to own a rich user profile/realm model, while this platform needs IAM to avoid becoming UMS or app-domain authority and to keep PII out of tokens/events. Lightweight access tokens and mapper discipline help, but must be proven by contract tests and admin policy locks.
- Keycloak extension points/SPIs can likely support event publication and custom policies, but an outbox-grade delivery model may need a sidecar or extension backed by Keycloak's supported event/listener surfaces. This needs deeper prototype/research before design lock.

## ZITADEL

### Verified facts

- ZITADEL recommends authorization code with PKCE for user-agent, native, and web clients, and recommends JWT bearer with private key for machine-to-machine clients. Source: [ZITADEL recommended OIDC/OAuth flows](https://zitadel.com/docs/guides/integrate/login/oidc/oauth-recommended-flows).
- ZITADEL supports passkeys/passwordless authentication. Source: [ZITADEL passkeys](https://zitadel.com/docs/concepts/features/passkeys).
- ZITADEL service accounts can authenticate using private key JWT, client credentials, or personal access tokens for ZITADEL APIs; service-account docs also cover client credentials and JWT profile flows. Sources: [Access ZITADEL APIs](https://zitadel.com/docs/guides/integrate/zitadel-apis/access-zitadel-apis), [OAuth client credentials for service accounts](https://zitadel.com/docs/guides/integrate/service-accounts/client-credentials), [ZITADEL grant types](https://zitadel.com/docs/apis/openidoauth/grant-types).
- ZITADEL Actions can customize behavior on API calls, events, or functions; Actions are also described for custom workflows and token/login behavior. Sources: [ZITADEL Actions v2](https://zitadel.com/docs/concepts/features/actions_v2), [Using Actions](https://zitadel.com/docs/guides/integrate/actions/usage).
- ZITADEL has an Event API; the docs state ZITADEL uses event sourcing and every action/change generates a stored event that can be retrieved and used for integration. Source: [ZITADEL Event API](https://zitadel.com/docs/guides/integrate/zitadel-apis/event-api).
- ZITADEL implements OAuth 2.0 token exchange for scope, audience, subject changes, impersonation, and delegation; its guide recommends limiting token exchange to confidential clients because of trust implications. Source: [ZITADEL token exchange](https://zitadel.com/docs/guides/integrate/token-exchange).
- ZITADEL v3 source licensing moved to AGPL-3.0; ZITADEL offers commercial licensing/enterprise self-hosting paths. Sources: [ZITADEL LICENSING.md](https://github.com/zitadel/zitadel/blob/main/LICENSING.md), [ZITADEL v3 announcement](https://zitadel.com/blog/zitadel-v3-announcement), [ZITADEL self-hosted](https://zitadel.com/self-hosted).
- ZITADEL pricing currently advertises a free plan and a Pro plan with daily active user allowances; pricing is not a stable design input and must be rechecked at procurement time. Source: [ZITADEL pricing](https://zitadel.com/pricing).

### Inference for our requirements

- ZITADEL lines up well with a multi-app first-party portfolio because projects/apps, service users, passkeys, Actions, and Event API are productized.
- Event sourcing and Event API are promising for IAM lifecycle event projections, but we still need to verify whether we can produce exactly the PII-free event envelope, ordering, correlation ID, replay, and transactional guarantees required by UMS without a separate platform outbox.
- AGPL/commercial licensing is a first-order decision if we plan to modify/self-host ZITADEL. If managed ZITADEL is used, data boundary and export/portability review become first-order.

## Ory stack

### Verified facts

- Ory Hydra is an OAuth 2.0 and OpenID Connect server written in Go; Ory describes it as OpenID Certified and says it handles token issuance, consent management, client registration, and cryptographic key storage, but does not manage users/passwords. It delegates authentication to a login provider such as Ory Kratos or a custom system through login/consent flow. Source: [Ory Hydra product page](https://www.ory.com/hydra).
- Hydra supports authorization code with PKCE, client credentials, refresh token, device authorization, token exchange, and JWT bearer profile for client authentication. Source: [Ory Hydra product page](https://www.ory.com/hydra).
- Ory documents custom login and consent flows for integrating OAuth/OIDC with a user database, login UI, consent logic, and consent UI. Source: [Ory user login and consent flow](https://www.ory.com/docs/oauth2-oidc/custom-login-consent/flow).
- Ory Hydra refresh tokens are single-use; on reuse, Ory treats the event as a leaked token and revokes the token chain for that consent. Source: [Ory OAuth2 debug guide](https://www.ory.com/docs/hydra/debug).
- Ory docs describe JWT access tokens, revocation checks through introspection, and opaque/JWT token tradeoffs. Source: [Ory opaque and JWT access tokens](https://www.ory.com/docs/oauth2-oidc/jwt-access-token).
- Ory Kratos is an API-first identity and user-management system for registration, login, recovery, verification, MFA, profile/account management, identity schemas/traits, and admin APIs. Source: [Ory Kratos repository](https://github.com/ory/kratos).
- Ory Kratos marketing/docs state support for FIDO2/WebAuthn, TOTP, passwordless flows, custom traits and schemas, self-hosted and managed deployment models. Source: [Ory Kratos page](https://www.ory.com/kratos).
- Ory Actions supports user-related event hooks including login, registration, recovery, verification, and settings update; Ory Network also has live event streams for sign-ups, logins, M2M tokens, and more under enterprise contracts. Sources: [Ory hooks/actions](https://www.ory.com/docs/kratos/hooks/configure-hooks), [Ory live events](https://www.ory.com/docs/actions/live-events).
- Ory Hydra's repository is Apache-2.0 licensed; Ory also offers Enterprise License and managed Ory Network paths. Sources: [Ory Hydra repository](https://github.com/ory/hydra), [Ory Hydra quickstart/OEL note](https://www.ory.com/docs/oel/hydra/quickstart).

### Inference for our requirements

- Ory Hydra is especially attractive for a hybrid architecture because it is intentionally not the user/profile system. Our IAM can own Human Identity, identifier protection, App Activation, outbox, and PII rules while Hydra owns protocol issuance.
- Using Hydra alone means we must build login, factor, verification, recovery, sessions, admin, and lifecycle products. Adding Kratos reduces that burden but introduces its identity-schema/traits model, which may need careful minimization to avoid duplicating UMS profile data.
- Ory's single-use refresh-token behavior aligns with the required refresh-reuse negative test, but any custom app-session/refresh-family semantics need to map cleanly to Hydra consent/session records.

## Managed providers: Auth0 and Amazon Cognito

### Verified facts: Auth0

- Auth0 documents OAuth/OIDC flow selection for server-side web apps, SPAs, machine-to-machine apps, private key JWT, mTLS, and client credentials. Source: [Auth0 authentication and authorization flows](https://auth0.com/docs/get-started/authentication-and-authorization-flow).
- Auth0 supports refresh-token rotation; when a refresh token is exchanged, the previous refresh token is invalidated, and reuse detection is intended to mitigate replay. Source: [Auth0 refresh-token rotation](https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation).
- Auth0 has Actions extensibility for flows, including client-credentials exchange in its flow docs. Source: [Auth0 authentication and authorization flows](https://auth0.com/docs/get-started/authentication-and-authorization-flow).
- Auth0 pricing is MAU/plan/feature driven and changes over time. Source: [Auth0 pricing](https://auth0.com/pricing).

### Verified facts: Amazon Cognito

- Amazon Cognito's token endpoint supports authorization code sessions, M2M sessions through client credentials, and refresh-token sessions. It recommends PKCE for authorization code sign-in. Source: [Amazon Cognito token endpoint](https://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html).
- Cognito documents refresh-token rotation as an advanced security configuration. Source: [Cognito refresh tokens](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-refresh-token.html).
- Cognito docs state authorization code grant is the only way to get ID, access, and refresh tokens from the authorization server. Source: [Cognito OAuth grants](https://docs.aws.amazon.com/cognito/latest/developerguide/federation-endpoints-oauth-grants.html).
- AWS documents Cognito M2M/client-credentials support and pricing dimensions for user-pool MAUs and M2M token request volume; there is no free tier for M2M token requests. Sources: [AWS Cognito M2M security blog](https://aws.amazon.com/blogs/security/how-to-monitor-optimize-and-secure-amazon-cognito-machine-to-machine-authorization/), [Cognito pricing](https://aws.amazon.com/cognito/pricing/), [Cognito cost tracking](https://docs.aws.amazon.com/cognito/latest/developerguide/tracking-cost.html).

### Inference for our requirements

- Managed providers reduce infrastructure and patching burden, and can be suitable if the platform accepts their identity/profile/user-pool object model.
- The main unresolved questions are data boundary and portability: whether raw verified identifiers and authentication telemetry can stay within acceptable IAM custody; whether app-bound token claims can be PII-free by policy; whether event emission can be made transactional/idempotent enough for UMS; and whether cross-app App Activation can be modeled without creating separate product identities.
- Managed providers are not eliminated, but they require early proof around PII, event replay, custom app-registration governance, delegated access semantics, and long-term cost under MAU plus M2M token volume.

## Hybrid external protocol-engine approach

### Verified facts

- Ory Hydra explicitly supports using any existing identity provider through login and consent flow and does not manage users/passwords. Source: [Ory Hydra product page](https://www.ory.com/hydra).
- Spring Authorization Server exposes the protocol core as configurable Spring components, including registered clients, authorizations, token settings, token generation/customization, and JWK/JWT configuration. Sources: [Spring SAS core model](https://docs.spring.io/spring-authorization-server/reference/core-model-components.html), [Spring SAS configuration model](https://docs.spring.io/spring-authorization-server/reference/configuration-model.html).

### Inference for our requirements

- A hybrid model can keep our strongest invariants under direct control: Human Identity, Verified Identifier vault/encryption, deterministic dev-only identity flow, Product Security Policy, App Activation, PII-free outbox events, UMS integration, admin/support boundaries, and service-owned profiles.
- The protocol engine must still be treated as production-critical security infrastructure. We would need explicit conformance tests, key-rotation tests, refresh-reuse tests, redirect/PKCE negatives, session outage behavior, and resource-server validation contracts.
- Hybrid has the highest integration-design load but may offer the cleanest way to prevent a vendor/product's user-profile model from leaking into UMS and app domains.

## Cross-cutting requirement fit

### Client portfolio

Verified:

- SAS, Keycloak, ZITADEL, Ory Hydra, Auth0, and Cognito all support authorization-code-style user flows and machine-to-machine/client-credential-style flows in their docs.
- SAS, ZITADEL, Ory, Cognito, and Keycloak docs explicitly mention PKCE or PKCE enforcement/recommendation.

Inference:

- All candidates can plausibly support native public clients with Authorization Code + S256 PKCE, confidential server web apps, and M2M workloads. Direct-token SPAs should remain disabled by platform policy regardless of provider capability.

### Factors, passkeys, and recovery

Verified:

- Keycloak, ZITADEL, and Ory Kratos have documented WebAuthn/passkey/FIDO2 support. SAS by itself does not provide a full end-user factor/recovery product in the cited docs.

Inference:

- If passkey-first UX and recovery are central, productized IAMs reduce build burden. SAS/standalone Hydra require building or integrating factor/recovery journeys.

### Identifier and data boundaries

Verified:

- Keycloak, ZITADEL, Kratos, Cognito, and Auth0 all have user/profile/identity stores. Hydra alone does not manage users/passwords. SAS leaves data model implementation to us.

Inference:

- The cleanest boundary options are SAS-custom IAM or Hydra-hybrid, because the identifier vault and PII-free event model can be first-class. Full IAM products need strict claim-mapper/profile minimization and tests proving PII never enters tokens/events/logs consumed by apps.

### SSO, refresh families, and revocation

Verified:

- Keycloak has SSO sessions and not-before revocation policy; Ory has single-use refresh tokens and reuse chain revocation; Auth0 and Cognito support refresh-token rotation; SAS has token settings for refresh reuse and stores authorizations through `OAuth2AuthorizationService`.

Inference:

- Ory/Auth0/Cognito provide closest off-the-shelf refresh-rotation semantics. SAS can implement the exact model but needs custom family-state logic. Keycloak must be configured/proven for the specific refresh-family reuse response we want.

### Workload identity and delegated service access

Verified:

- Keycloak service accounts, ZITADEL service accounts, Ory Hydra client credentials/JWT bearer, Cognito M2M, Auth0 M2M, and SAS client credentials all cover workload-style client authentication.
- ZITADEL and Ory Hydra document token exchange; Spring docs include token exchange in supported features.

Inference:

- Named delegated access workflows require additional policy beyond generic client credentials. Token exchange can be a mechanism, but the platform still needs a product rule that preserves both human subject and workload actor, narrow audience/scope, short lifetime, no refresh, and audit evidence.

### Events, outbox, and app integration

Verified:

- ZITADEL has Event API and Actions; Ory has Actions/hooks and live event streams; Keycloak has server-side extensibility and events in its admin/server-development docs; managed providers have hooks/actions/triggers; SAS leaves event publication to the application.

Inference:

- Transactional outbox semantics are easiest when our code owns the write transaction, as with SAS-custom or hybrid IAM-owned database. Product/provider event hooks may be eventually consistent and need replay/reconciliation design before UMS can rely on exactly-once/idempotent profile creation.

### Keys and operations

Verified:

- SAS and Ory expose JWK/JWT/key configuration; Hydra documents cryptographic key storage; Keycloak has realm/client key and revocation/admin concepts; managed providers own more operational surface.

Inference:

- Managed providers reduce key custody burden but constrain crypto policy and outage behavior. Self-hosted products move uptime, upgrades, backups, key rotation, incident response, and abuse controls onto us. SAS/hybrid maximizes custom control and operational responsibility.

### Portability, licensing, and cost

Verified:

- Keycloak is Apache-2.0. Hydra is Apache-2.0. ZITADEL v3 source is AGPL-3.0-only with commercial alternatives. Auth0/Cognito/ZITADEL Cloud/Ory Network are service-pricing models. Cognito charges across MAU and M2M/token-request dimensions; Auth0 is plan/MAU/feature driven.

Inference:

- Apache-licensed self-hosted options reduce license risk but not operating cost. AGPL/commercial products require legal review. Managed providers shift cost from engineering ops to recurring service usage and can create switching costs in user store, actions, logs, and policy definitions.

## Research gaps before stack selection

- Confirm current passkey, native-app, refresh-rotation, token-exchange, logout, and revocation behavior by running provider-specific proof tests, not only docs.
- Determine whether Keycloak/ZITADEL/Ory provider events can satisfy our exact outbox/replay/idempotency/correlation requirements or whether an IAM-owned outbox must wrap them.
- Validate PII-free token and event contracts with negative tests for email, phone, credential material, access tokens, refresh tokens, and provider-specific default claims.
- For managed providers, verify data residency, custom domain/issuer, export/delete, audit log access, breach response, rate limits, pricing at target MAU/M2M volumes, and contract terms.
- For ZITADEL, complete AGPL/commercial-license review before any self-hosted modification decision.
- For SAS or hybrid, estimate build surface for passkeys, recovery, device/session management, admin/support tools, abuse controls, and security certification/conformance.

## Sources

- Spring Authorization Server reference: https://docs.spring.io/spring-authorization-server/reference/index.html
- Spring SAS getting started: https://docs.spring.io/spring-authorization-server/reference/getting-started.html
- Spring SAS core model: https://docs.spring.io/spring-authorization-server/reference/core-model-components.html
- Spring SAS configuration model: https://docs.spring.io/spring-authorization-server/reference/configuration-model.html
- Spring SAS JPA guide: https://docs.spring.io/spring-authorization-server/reference/guides/how-to-jpa.html
- Spring Security OAuth 2.1 Authorization Server: https://docs.spring.io/spring-security/reference/servlet/oauth2/authorization-server/index.html
- Keycloak server administration guide: https://www.keycloak.org/docs/latest/server_admin/index.html
- Keycloak Admin REST API: https://www.keycloak.org/docs-api/latest/rest-api/index.html
- Keycloak repository/license: https://github.com/keycloak/keycloak
- ZITADEL recommended flows: https://zitadel.com/docs/guides/integrate/login/oidc/oauth-recommended-flows
- ZITADEL passkeys: https://zitadel.com/docs/concepts/features/passkeys
- ZITADEL service account/API access: https://zitadel.com/docs/guides/integrate/zitadel-apis/access-zitadel-apis
- ZITADEL client credentials: https://zitadel.com/docs/guides/integrate/service-accounts/client-credentials
- ZITADEL grant types: https://zitadel.com/docs/apis/openidoauth/grant-types
- ZITADEL Actions v2: https://zitadel.com/docs/concepts/features/actions_v2
- ZITADEL Actions usage: https://zitadel.com/docs/guides/integrate/actions/usage
- ZITADEL Event API: https://zitadel.com/docs/guides/integrate/zitadel-apis/event-api
- ZITADEL token exchange: https://zitadel.com/docs/guides/integrate/token-exchange
- ZITADEL licensing: https://github.com/zitadel/zitadel/blob/main/LICENSING.md
- ZITADEL v3 announcement: https://zitadel.com/blog/zitadel-v3-announcement
- ZITADEL pricing: https://zitadel.com/pricing
- Ory Hydra product page: https://www.ory.com/hydra
- Ory Hydra repository/license: https://github.com/ory/hydra
- Ory Hydra custom login/consent: https://www.ory.com/docs/oauth2-oidc/custom-login-consent/flow
- Ory refresh-token debug guide: https://www.ory.com/docs/hydra/debug
- Ory JWT/opaque access-token docs: https://www.ory.com/docs/oauth2-oidc/jwt-access-token
- Ory Kratos repository: https://github.com/ory/kratos
- Ory Kratos product page: https://www.ory.com/kratos
- Ory Kratos hooks/actions: https://www.ory.com/docs/kratos/hooks/configure-hooks
- Ory live events: https://www.ory.com/docs/actions/live-events
- Auth0 flow guidance: https://auth0.com/docs/get-started/authentication-and-authorization-flow
- Auth0 refresh-token rotation: https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation
- Auth0 pricing: https://auth0.com/pricing
- Amazon Cognito token endpoint: https://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html
- Amazon Cognito refresh tokens: https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-refresh-token.html
- Amazon Cognito OAuth grants: https://docs.aws.amazon.com/cognito/latest/developerguide/federation-endpoints-oauth-grants.html
- Amazon Cognito M2M security blog: https://aws.amazon.com/blogs/security/how-to-monitor-optimize-and-secure-amazon-cognito-machine-to-machine-authorization/
- Amazon Cognito pricing: https://aws.amazon.com/cognito/pricing/
- Amazon Cognito cost tracking: https://docs.aws.amazon.com/cognito/latest/developerguide/tracking-cost.html
