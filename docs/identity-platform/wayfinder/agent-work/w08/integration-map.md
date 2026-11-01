# W-8 integration map

Authoritative scope: [W-8](../../work-items.md#w-8--activate-dutch-and-append-one-onboarding-intent), [activation model](../../feature-implementation-plan.md#app-subject-and-activation-model) and [event contracts](../../feature-implementation-plan.md#event-contracts).

```text
W08-A prerequisites/state ─┐
                           ├─> W08-C first activation ─┬─> W08-RC ─┐
W08-B onboarding intent ───┘                          └─> W08-RS ─┴─> W08-F
```

A and B are parallel-safe: disjoint write ownership and disjoint migrations (V10 activation, V11 intent).
C owns the composition, the end-to-end PostgreSQL scenario, the parent evidence and the clean gate.
Gradle runs serialize through the `iam-build` execution lease; C owns `gradle-build`.
