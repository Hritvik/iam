Type: research
Status: resolved
Assignee: Codex/identity_platform_research
Parent: [Specify the shared first-party Identity Platform](../map.md)

# Research candidate Identity Platform approaches

## Question

What verified capabilities, extension models, operational burdens, security properties, portability constraints, and costs distinguish Spring Authorization Server, mature self-hosted identity products, composable identity platforms, managed providers, and a custom policy layer around an external protocol engine for this first-party portfolio?

## Answer

The verified comparison is captured in [Identity Platform Options Research](../../research/identity-platform-options.md). Spring Authorization Server is a customizable protocol foundation rather than a complete IAM product; Keycloak is the strongest complete self-hosted baseline but requires strict profile/claim minimization; ZITADEL provides productized multi-app, passkey, workload, action, and event capabilities with material AGPL/commercial considerations; Ory Hydra/Kratos provides a composable and especially relevant hybrid boundary; and Auth0/Cognito reduce infrastructure burden while increasing provider-shape, portability, data-boundary, event, and recurring-cost constraints.

All candidates plausibly cover the core client portfolio, but none is selected by research alone. The decisive proof points are passkey/recovery product surface, exact refresh-family behavior, PII-free tokens and events, App Activation fit, transactional event delivery, workload/delegation semantics, key custody, provider portability, operating burden, and total cost. Provider-specific proof tests and legal/procurement facts remain inputs to the later stack-selection decision.
