# Independent review 02 — W07-A through W07-D remediation

- Reviewer: `REVIEWER-02`
- Gates: focused 35/35, DpopPersistenceIntegrationTest 16/16, contractTest 8/8, full unit 322/322, full integration 286/286

## Verdicts

| Packet | Verdict |
|---|---|
| W07-A | APPROVE (low A-3, A-4 remain) |
| W07-B | APPROVE (low B-2, B-3 remain) |
| W07-C | APPROVE (low C-2 remains) |
| W07-D | APPROVE (low D-3, D-4, D-5 remain) |

All medium/high findings from review 01 are verified fixed.

## New findings

- **NEW MEDIUM (W07-E)**: replay retention is not cross-checked against proof maximum age + skew + margin. `DpopApplicationConfiguration`/`DefaultTokenEndpointOrchestrator` allow retention 120 s while the verifier allows age 120 + skew 30, creating up to a 30 s replay window. Must be closed in W07-E.
- NEW LOW: resource-verifier correlation is not normalized before persistence.
- NEW LOW: `newest()` is highest-readable, not necessarily the write version.
- NEW LOW: Jdbc store alias wiring has no end-to-end test.
- NEW LOW: evidence changed-files statements are stale.
