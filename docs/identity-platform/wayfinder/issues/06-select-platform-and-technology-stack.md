Type: grilling
Status: resolved
Assignee: Codex
Parent: [Specify the shared first-party Identity Platform](../map.md)
Blocked by: 02, 03, 04, 05

# Select the Identity Platform and technology stack

## Question

Which build, self-hosted product, composable platform, managed service, or hybrid protocol-engine approach best satisfies the settled requirements, extensibility, security, operating model, portability, and cost—and what repository/runtime shape follows from that choice?

## Decision

Build the Identity Platform as a **JVM-first, externally portable modular monolith** using:

- a current supported Java LTS runtime;
- Spring Boot and Spring Security;
- Spring Authorization Server as the OAuth 2.0 and OpenID Connect protocol engine;
- PostgreSQL as IAM's independently owned durable store;
- Flyway for forward-only, versioned database migrations;
- a transactional outbox for lifecycle integration; and
- separately scalable workers only where measured throughput, isolation, or availability requirements justify them.

This is a platform-foundation decision rather than a fastest-launch decision. IAM owns its authentication ceremonies, passkey and verified-channel flows, recovery, administration, abuse controls, sessions, authorization state, and operational response. Coding agents are development leverage, not a reason to accept additional production runtimes or distributed consistency boundaries.

## Repository and runtime shape

- Keep one cohesive IAM deployable initially, divided into explicit internal modules around Identity, Identifier, Factor, Authentication, Recovery, Session, Authorization, Registration, Activation, Workload Identity, Audit, and Outbox responsibilities.
- Enforce module boundaries in code and tests. Modules communicate through application interfaces and immutable domain messages rather than accessing one another's persistence representations.
- Run asynchronous outbox publication and maintenance jobs as modes of the same versioned application initially. Extract a worker only when independent scaling or failure isolation is demonstrated.
- Give IAM one database per environment and exclusive schema ownership. Product services, including UMS, never query IAM tables.
- Keep public HTTP, OAuth/OIDC, manifest, and event contracts language-neutral and versioned. Dutch, Midas, Jarvis, and future applications remain free to use other technology stacks.
- Keep deployment artifacts reproducible and environment-neutral. Runtime secrets, signing material, and provider credentials enter through an approved secret-management interface and never through source-controlled manifests.

## Alternatives considered

### Keycloak with extensions

Keycloak is the strongest speed-first alternative because it supplies a mature self-hosted identity product, including WebAuthn/passkey capabilities and administrative workflows. It was not selected because the settled requirements prioritize exact domain boundaries, transactional PII-free lifecycle events, custom activation and recovery semantics, and long-term control. Achieving those properties would require substantial extensions while making Keycloak's internal model and upgrade lifecycle part of the platform contract.

### Custom Identity Core with Ory Hydra/Kratos

Ory offers a strong composable protocol-engine approach and clearer separation between OAuth and identity concerns. It was not selected because a sole operator would inherit additional deployables, stores, upgrades, secrets, monitoring, and cross-service consistency workflows. Identity mutation plus durable event publication would no longer be a single local transaction.

### ZITADEL or managed IDaaS

These reduce initial feature development but introduce material constraints around provider data models, portability, specialized lifecycle/delegation semantics, vendor cost, and operational control. They are not the default platform foundation. A managed provider may be reconsidered only through a new decision if the operating model or requirements materially change.

## Consequences and guardrails

- Spring Authorization Server is treated as protocol infrastructure, not a complete identity product. The specification must explicitly design every user-facing and administrative security workflow that it does not provide.
- Do not implement OAuth/OIDC primitives, token formats, signing algorithms, or WebAuthn cryptography from scratch when maintained standards-based libraries exist.
- Prefer one secure deployable over premature IAM microservices. Extraction requires a written driver and preservation of the same contracts and ownership boundaries.
- Platform code may use Java-specific internal types; no external contract may expose Java serialization, framework classes, database identifiers, or implementation-specific claims.
- Direct access from applications to IAM persistence remains prohibited even when co-located operationally.
- Supported framework/runtime versions are pinned during implementation planning and upgraded through tested dependency policy rather than frozen by this specification.
