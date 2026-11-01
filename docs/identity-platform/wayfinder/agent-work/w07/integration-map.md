# W-7 integration map

Authoritative scope: [W-7](../../work-items.md#W-7--enforce-native-dpop-and-durable-replay-protection) and [decisions](../../artifacts/work-item-07-decisions.md).

```text
W07-A proof/target ─┐
W07-B state/keys ──┼─> W07-E issuance composition ─> W07-I full slice ─┬─> W07-RC ─┐
W07-C deadline ────┤                                               └─> W07-RS ─┴─> W07-F
W07-D boundary ────┘
```

W07-A through W07-D are parallel-safe by declared write ownership. W07-E consumes their reviewed interfaces. W07-I exclusively owns shared integration tests, contract catalogs, parent evidence, and the clean gate. Gradle clean/integration runs are serialized through W07-I.

The parent is accepted only through W07-F after W07-RC and W07-RS accept the same W07-I evidence revision with no unresolved medium-or-higher findings. A rejection reopens the owning packet, including W07-I for shared integration work, invalidates the prior W07-I gate, and requires a new W07-I evidence revision followed by both reviews.

Lock groups are exclusive claim leases enforced by the board transition scripts. A packet may edit or execute against a declared shared resource only while holding every corresponding group. One atomic board claim acquires all groups together. `gradle-build` serializes Gradle output, and `dpop-integration` serializes shared PostgreSQL/integration fixtures. Release or handoff relinquishes the claim and its groups.
