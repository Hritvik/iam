# W08-RS — Independent security and privacy review

## Objective

Review the integrated W-8 slice for privacy, event allowlist and fail-closed behaviour.

## Authority and inputs

- Packets W08-A..C, [W-8 evidence](../evidence/W08-C.md), [W-7 pattern](../w07/evidence/W07-RS.md).

## Outputs and ownership

Own only `evidence/W08-RS.md`. Do not change production code.

## Acceptance

- The event and its envelope contain only the allowlisted app-scoped fields.
- No identifier, credential, token, global identity or subject leakage in rows, logs, errors or diagnostics.
- Pending activation emits nothing; failures fail closed.
- No critical, high or medium finding remains.

## Verification

Run the privacy/contract suites and the parent gate; record exact counts.

## Handoff

- Current state: draft.
- Next action: review the same W08-C revision.
