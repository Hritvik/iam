# W-9 integration map

Authoritative scope: [W-9](../../work-items.md#w-9--relay-onboarding-and-expose-the-repair-snapshot), [persistence model](../../feature-implementation-plan.md#persistence-and-transaction-model) and the snapshot contract.

```text
W09-A relay/leases ─┐
                    ├─> W09-C producer proof ─┬─> W09-RC ─┐
W09-B snapshot ─────┘                        └─> W09-RS ─┴─> W09-F
```

A and B are parallel-safe (disjoint packages and one migration owned by B). C owns the composed
producer test, the messaging wiring file, the evidence artifact and the clean gate.
