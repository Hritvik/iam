# W07-RC — Independent correctness and database review

## Objective

Independently determine whether integrated W-7 meets its protocol, database, concurrency, migration, and evidence requirements.

## Scope

Read all W-7 code, contracts, tests, decisions, packets, and evidence. This packet is read-only except for its evidence report.

## Acceptance

- Report every critical, high, and medium finding with exact evidence.
- Re-run bounded tests where useful without colliding with another build.
- Verify claims rather than trusting packet checkpoints.
- Accept only with no unresolved medium-or-higher correctness/database finding.

## Verification

Run the smallest independent unit, PostgreSQL, migration, concurrency, and full-context commands needed to validate or falsify the evidence. Record every command and result in `evidence/W07-RC.md`; serialize any Gradle use through the board lock group.

## Handoff

- Current state: draft until W07-I is integrated.
- Next action: perform a clean-room review without the intended answer from implementers.
