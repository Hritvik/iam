# W-10 contract handoff — Dutch mapping and profile contracts

Status: **complete and accepted in the Dutch repository** (see `~/repositories/dutch/docs/wayfinder/w10/README.md`)
Owner: Dutch (`~/repositories/dutch`)
IAM role: supply the read-only imported bundle and the accepted shapes; IAM must not author or edit Dutch
contracts, and must not publish `iam.identity.verified.v1`.

## Why this is a separate workstream

W-10's acceptance says the mapping event and profile HTTP formats are **Dutch-owned**. The IAM repo's
`contracts/**` bundle is immutable consumer input. Therefore the W-10 packet board belongs in the Dutch
repository (suggested root: `docs/wayfinder/w10/`), and this session must not edit Dutch files without
authorization.

## Current Dutch contract drift

| File | Current (legacy prototype) | Problem |
|---|---|---|
| `contracts/events/iam/json-schema/iam.identity.verified.v1.schema.json` | identity-lifecycle event | Forbidden: the plan states there is no `iam.identity.verified.v1` production or bridge event |
| `contracts/events/ums/json-schema/ums.member.mapping.changed.v1.schema.json` | payload `identityId, memberId, mappingVersion, lifecycleState` | Leaks a global identity; missing `appRegistrationId`, `appSubject`, `profileState`; wrong event name; UUIDs instead of the IAM envelope's `evt_`/`cor_`/aggregate shapes |
| `contracts/events/asyncapi.yaml` | publishes both legacy channels | Publishes the forbidden identity event and the superseded mapping event |
| `contracts/http/gateway/openapi.yaml` `/api/v1/me` | returns `identityId, memberId, lifecycleState, mappingVersion` | Leaks the global identity, no profile body, no `/api/v1/me/profile-state` |
| `contracts/http/fixtures/error/profile-required.json` | UUID correlation, ad-hoc message | Must use the IAM error envelope and `cor_` correlation |
| `contracts/http/fixtures/success/profile-ready.json` | legacy mapping fields | Must be a Dutch-owned Member Profile without identity/subject leakage |

The Dutch harness is `contracts/validate-contracts.mjs` with `npm test` / `npm run validate` in
`contracts/`.

## Target set to author

1. **`dutch.member-profile.mapping-changed.v1`** inside the IAM shared envelope
   (`contracts/events/event-envelope.schema.json` imported from the IAM bundle). Payload exactly:
   `appRegistrationId, appSubject, memberId, mappingVersion, profileState, lifecycleState`.
   No `identityId`, no identifiers, no credentials, no tokens.
2. **Profile HTTP**, split per D-13:
   - `GET /api/v1/me/profile-state` → `200 { data: { state } }` where `state` is
     `PROFILE_REQUIRED | PROFILE_PROVISIONING | PROFILE_READY` plus safe retry guidance only.
   - `GET /api/v1/me` → `409` `error.code=profile_required` until ready; then `200` with the
     Dutch-owned Member Profile. Neither response echoes App Subject or any global identity.
3. **Fixtures**: valid mapping event; valid profile-state variants; valid profile-ready; forbidden-field
   fixtures that each fail for the asserted reason (global identity, App Subject in HTTP, identifier,
   credential, token, undeclared field).
4. **Pinned IAM bundle**: record the accepted `iam-contracts-1.0.0.zip` sha256
   `7bb76067a0e2e5ea0efd1e4aca981c3ef3fead2abb7f9e467fadca8dadc81195` as the immutable consumer input.

## Suggested board (Dutch repo)

- `W10-A` mapping event schema + AsyncAPI channel replacement (remove `iam.identity.verified.v1`).
- `W10-B` profile HTTP OpenAPI + response schemas + error envelope use.
- `W10-C` fixtures and harness updates (`npm test` red→green), plus the bundle pin record.
- Reviews: correctness/DB not applicable; one contract/privacy review and one consumer-compatibility
  review, then acceptance.

## Verification

```bash
cd ~/repositories/dutch/contracts
npm test
npm run validate
```

## Risks and preconditions

- The Dutch repo has uncommitted working-tree changes (`git status` shows modified build files and a
  deleted `DutchApplication`); preserve them and do not reset.
- Removing `iam.identity.verified.v1` and the legacy mapping event may break existing UMS code; the
  board must include the consumer sweep before deletion.
- This must be executed with explicit authorization to work in the Dutch repository.
