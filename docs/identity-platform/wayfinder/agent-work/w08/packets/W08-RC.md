# W08-RC — Independent correctness and database review

## Objective

Review the integrated W-8 slice for correctness, transaction, concurrency and database authority.

## Authority and inputs

- Packets W08-A..C, [W-8 evidence](../evidence/W08-C.md), [W-7 pattern](../w07/evidence/W07-RC.md).

## Outputs and ownership

Own only `evidence/W08-RC.md`. Do not change production code.

## Acceptance

- State machine and prerequisite evaluation are closed and literal.
- Expected-version, idempotency and concurrency produce exactly one logical result.
- Rollback seams are complete; ACLs and constraints are least-privilege.
- No critical, high or medium finding remains.

## Verification

Run the parent gate plus the focused activation and intent suites; record exact counts.

## Handoff

- Current state: draft.
- Next action: review the frozen W08-C revision.
