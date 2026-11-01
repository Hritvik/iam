# W-8 red/green and decision record

- Scope: strict Dutch activation plus one PII-free onboarding intent (Slice C, IAM producer side only).
- Board: [`agent-work/w08`](../agent-work/w08/board.json).

## Red/green summary

| Packet | RED | GREEN |
|---|---|---|
| W08-A | evidence reads failed under `iam_runtime` least privilege | activation state machine + prerequisite evaluation on PostgreSQL |
| W08-B | removing the conflict guard made a retried append fail | one event + delivery per activation version |
| W08-C | activation could not be composed with the intent; repo gate red from the new FK/migrations | first-activation transaction proven end to end |

## Decisions

- Activation prerequisites are evaluated from the app's registered `policy_activation_evidence` set; an empty set is `app_not_registered`, never satisfied.
- The activation row must reference the exact `(app, identity, subject)` mapping; both FKs and an explicit tuple guard enforce it.
- The onboarding payload is built from the canonical `OnboardingReadyPayload` and fingerprinted with RFC 8785 + SHA-256; the writer recomputes it before persistence.
- `append_onboarding_intent` binds every payload field to the activation and to the app registration's environment, and rejects a divergent duplicate instead of returning `EXISTING`.
- Activation is conditional on both `iam.activation.enabled` and `iam.app-subject.enabled`; the intent writer lives in its own property-gated messaging configuration.
- No production activation entry point exists yet; the deterministic fixture and activation surface are later work. This is recorded as a deferral, not a silent gap.

## Evidence

- `agent-work/w08/evidence/W08-A.md`, `W08-B.md`, `W08-C.md`, `W08-RC.md`, `W08-RS.md`.
- Final gate: 347 unit, 309 PostgreSQL integration, 8 contract; 92.71% line / 80.10% branch.
