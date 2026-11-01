# Context Map

## Contexts

- [Identity Platform](./IAM-CONTEXT.md) — provides shared identity and authentication for first-party applications operated under the same umbrella.
- **Dutch** — owns Dutch Member Profiles, shared-expense product behavior, obligations, balances, and settlements.
- **Midas** — owns its product profile, data, and domain authorization while consuming the shared Identity Platform.
- **Jarvis** — owns its product profile, data, and domain authorization while consuming the shared Identity Platform.
- **Future first-party applications** — integrate through reviewed App Registrations and app-scoped subjects without inheriting another product's profile or authorization model.

## Relationships

- **Identity Platform → Dutch**: IAM authenticates a Human Identity and publishes PII-free lifecycle facts; Dutch services authorize locally from app-bound tokens and service-owned projections.
- **Dutch → Identity Platform**: Dutch registers first-party clients, resource audiences, scopes, redirect policies, and App Activation prerequisites without transferring Member Profile or financial ownership to IAM.
- **Midas/Jarvis/future apps ↔ Identity Platform**: each application receives its own App Subject, activation, clients, audiences, scopes, sessions, and PII-free lifecycle integration while IAM retains the shared Human Identity and verified identifiers.
