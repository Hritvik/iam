# W07-RS — Independent security and privacy review

## Objective

Independently determine whether integrated W-7 is secure against proof confusion, replay, rotation, timeout, quota exhaustion, database privilege abuse, and sensitive-data leakage.

## Scope

Read all W-7 code, contracts, tests, decisions, packets, and evidence. This packet is read-only except for its evidence report.

## Acceptance

- Report every critical, high, and medium finding with exact evidence.
- Verify nonce/replay rotation semantics, signer deadlines, trusted target/network authority, diagnostics, errors, logs, metrics, database grants, and excluded endpoints.
- Re-run bounded tests where useful without colliding with another build.
- Accept only with no unresolved medium-or-higher security/privacy finding.

## Verification

Run the smallest independent proof, replay, rotation, timeout, privilege, endpoint, and privacy commands needed to validate or falsify the evidence. Record every command and result in `evidence/W07-RS.md`; serialize any Gradle use through the board lock group.

## Handoff

- Current state: draft until W07-I is integrated.
- Next action: perform a clean-room review without the intended answer from implementers.
