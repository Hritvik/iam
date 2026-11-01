# IAM contracts

This directory is the editable source of the language-neutral Identity Platform contracts. `catalog.yaml` is the canonical index. Contract documents use semantic versions independently from the IAM application version.

Run `./gradlew contractTest contractBundle` to validate every fixture and create `build/distributions/iam-contracts-1.0.0.zip` with its SHA-256 file. Consumers pin both values and treat extracted bundle contents as read-only. Generated bundles are build outputs and must not be edited or checked in.

The event surface intentionally publishes only the app-scoped onboarding event. `FIRST_ACTIVATION` is the normal first delivery; `RECONCILIATION` is reserved for a snapshot-derived repair fact and does not weaken aggregate version checks. It does not publish a global identity lifecycle event or any schema that permits identifiers, credentials, refresh/session tokens, or arbitrary event-specific payload maps.

The OAuth surface publishes the closed human access-token profile, mandatory DPoP proof and token-response shapes, and Authorization Server metadata. The compact access token is permitted only in the successful token response. It does not claim OIDC discovery, define an ID-token profile, or permit refresh issuance.
